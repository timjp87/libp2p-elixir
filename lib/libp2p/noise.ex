defmodule Libp2p.Noise do
  @moduledoc """
  noise-libp2p secure channel (Noise_XX_25519_ChaChaPoly_SHA256).

  This implements the handshake logic defined in `third_party/libp2p_specs/noise/README.md`.
  It is not yet wired to sockets; it operates on binary messages:
  - during handshake: the `noise_message` field (excluding the 2-byte length prefix)
  - after handshake: transport messages are AEAD ciphertext (excluding length prefix)
  """

  alias Libp2p.Identity
  alias Libp2p.Crypto.{PublicKeyPB, Secp256k1}
  alias Libp2p.Noise.HandshakePayloadPB

  @protocol_name "Noise_XX_25519_ChaChaPoly_SHA256"
  @sig_prefix "noise-libp2p-static-key:"
  @tag_len 16

  @type role :: :initiator | :responder

  @type cipher_state :: %{k: binary() | nil, n: non_neg_integer()}

  @type state :: %{
          role: role(),
          # symmetric state
          ck: binary(),
          h: binary(),
          cs: cipher_state(),
          # DH keys (25519)
          s_priv: binary(),
          s_pub: binary(),
          e_priv: binary() | nil,
          e_pub: binary() | nil,
          re: binary() | nil,
          rs: binary() | nil,
          # libp2p identity for signing/verification
          identity: Identity.t() | nil,
          remote_identity_key: {atom(), binary()} | nil
        }

  @spec new(role(), Identity.t()) :: state()
  def new(role, %Identity{} = identity) when role in [:initiator, :responder] do
    {s_pub, s_priv} = :crypto.generate_key(:ecdh, :x25519)
    {ck, h} = initialize_symmetric()

    %{
      role: role,
      ck: ck,
      h: h,
      cs: %{k: nil, n: 0},
      s_priv: s_priv,
      s_pub: s_pub,
      e_priv: nil,
      e_pub: nil,
      re: nil,
      rs: nil,
      identity: identity,
      remote_identity_key: nil
    }
  end

  # --- framing helpers (noise spec: 2-byte BE len prefix) ---
  @spec frame(binary()) :: binary()
  def frame(noise_message) when is_binary(noise_message) do
    if byte_size(noise_message) > 65_535, do: raise(ArgumentError, "noise_message too large")
    <<byte_size(noise_message)::unsigned-big-integer-size(16), noise_message::binary>>
  end

  @spec deframe(binary()) :: {binary(), binary()} | :more
  def deframe(bin) when is_binary(bin) do
    case bin do
      <<len::unsigned-big-integer-size(16), rest::binary>> when byte_size(rest) >= len ->
        <<msg::binary-size(len), tail::binary>> = rest
        {msg, tail}

      _ ->
        :more
    end
  end

  # --- handshake driver ---
  @doc """
  Initiator: produce first handshake message (message 1: `-> e`).
  """
  @spec initiator_msg1(state()) :: {binary(), state()}
  def initiator_msg1(%{role: :initiator, e_priv: nil} = st) do
    {e_pub, e_priv} = :crypto.generate_key(:ecdh, :x25519)
    st = %{st | e_pub: e_pub, e_priv: e_priv}
    st = mix_hash(st, e_pub)
    {e_pub, st}
  end

  @doc """
  Responder: consume msg1 and produce msg2 (message 2: `<- e, ee, s, es`).
  Returns `{msg2, st2}`.
  """
  @spec responder_msg2(state(), binary()) :: {binary(), state()}
  def responder_msg2(%{role: :responder, re: nil} = st, msg1) when is_binary(msg1) and byte_size(msg1) == 32 do
    # read initiator ephemeral
    st = %{st | re: msg1}
    st = mix_hash(st, msg1)

    # generate responder ephemeral
    {e_pub, e_priv} = :crypto.generate_key(:ecdh, :x25519)
    st = %{st | e_pub: e_pub, e_priv: e_priv}
    st = mix_hash(st, e_pub)

    # ee
    ee = dh_x25519(e_priv, msg1)
    st = mix_key(st, ee)

    # encrypt static noise public key (32 bytes)
    {enc_s, st} = encrypt_and_hash(st, st.s_pub)

    # es
    es = dh_x25519(st.s_priv, msg1)
    st = mix_key(st, es)

    # payload (encrypted)
    payload = make_handshake_payload(st.identity, st.s_pub)
    {enc_payload, st} = encrypt_and_hash(st, payload)

    msg2 = e_pub <> enc_s <> enc_payload
    {msg2, st}
  end

  @doc """
  Initiator: consume msg2 and produce msg3 (message 3: `-> s, se`).
  Returns `{msg3, st3, {cs_out, cs_in}}` where cipher states are ready for transport.
  """
  @spec initiator_msg3(state(), binary()) :: {binary(), state(), {cipher_state(), cipher_state()}}
  def initiator_msg3(%{role: :initiator, re: nil} = st, msg2) when is_binary(msg2) do
    if byte_size(msg2) < 32, do: raise(ArgumentError, "msg2 too short")
    <<re::binary-size(32), rest::binary>> = msg2
    st = %{st | re: re}
    st = mix_hash(st, re)

    # ee
    ee = dh_x25519(st.e_priv, re)
    st = mix_key(st, ee)

    # decrypt responder static noise pubkey
    {rs_pub, rest2, st} = decrypt_and_hash_exact(st, rest, 32)
    st = %{st | rs: rs_pub}

    # es
    es = dh_x25519(st.e_priv, rs_pub)
    st = mix_key(st, es)

    # decrypt and verify payload
    {payload, rest3, st} = decrypt_and_hash_to_end(st, rest2)
    _ = rest3
    st = verify_handshake_payload!(st, payload, rs_pub)

    # encrypt our static noise pubkey
    {enc_s, st} = encrypt_and_hash(st, st.s_pub)

    # se
    se = dh_x25519(st.s_priv, re)
    st = mix_key(st, se)

    payload3 = make_handshake_payload(st.identity, st.s_pub)
    {enc_payload, st} = encrypt_and_hash(st, payload3)

    msg3 = enc_s <> enc_payload
    {cs1, cs2} = split(st)
    # initiator: cs1 = sending, cs2 = receiving (Noise convention)
    {msg3, st, {cs1, cs2}}
  end

  @doc """
  Responder: consume msg3, verify payload, and return `{st3, {cs_in, cs_out}}`.
  """
  @spec responder_finish(state(), binary()) :: {state(), {cipher_state(), cipher_state()}}
  def responder_finish(%{role: :responder, rs: nil} = st, msg3) when is_binary(msg3) do
    # decrypt initiator static noise pubkey
    {rs_pub, rest2, st} = decrypt_and_hash_exact(st, msg3, 32)
    st = %{st | rs: rs_pub}

    # se
    se = dh_x25519(st.e_priv, rs_pub)
    st = mix_key(st, se)

    # decrypt and verify payload (rest of msg3)
    {payload, rest3, st} = decrypt_and_hash_to_end(st, rest2)
    _ = rest3
    st = verify_handshake_payload!(st, payload, rs_pub)

    {cs1, cs2} = split(st)
    # responder: cs1 = receiving, cs2 = sending (inverse)
    {st, {cs1, cs2}}
  end

  # --- transport messages (post-handshake) ---
  @doc """
  Encrypt a transport message with a `CipherState`.

  Per Noise message format, the output is `ciphertext || tag` (16 bytes tag).
  """
  @spec transport_encrypt(cipher_state(), binary(), binary()) :: {binary(), cipher_state()}
  def transport_encrypt(%{k: key, n: n} = cs, plaintext, ad \\ <<>>)
      when is_binary(plaintext) and is_binary(ad) do
    if key == nil, do: raise(ArgumentError, "cipher state has no key")
    nonce = <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, ad, true)
    {ciphertext <> tag, %{cs | n: n + 1}}
  end

  @doc """
  Decrypt a transport message with a `CipherState`.
  """
  @spec transport_decrypt(cipher_state(), binary(), binary()) :: {binary(), cipher_state()}
  def transport_decrypt(%{k: key, n: n} = cs, ciphertext_and_tag, ad \\ <<>>)
      when is_binary(ciphertext_and_tag) and is_binary(ad) do
    if key == nil, do: raise(ArgumentError, "cipher state has no key")
    if byte_size(ciphertext_and_tag) < @tag_len, do: raise(ArgumentError, "truncated transport message")
    nonce = <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
    ct_len = byte_size(ciphertext_and_tag) - @tag_len
    <<ct::binary-size(ct_len), tag::binary-size(@tag_len)>> = ciphertext_and_tag

    case :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ct, ad, tag, false) do
      :error -> raise(ArgumentError, "AEAD decrypt failed")
      pt -> {pt, %{cs | n: n + 1}}
    end
  end

  # --- symmetric state helpers (Noise Framework semantics) ---
  defp initialize_symmetric do
    # per Noise: if protocol name shorter than hashlen, pad with zeros; else hash.
    h0 =
      if byte_size(@protocol_name) <= 32 do
        @protocol_name <> :binary.copy(<<0>>, 32 - byte_size(@protocol_name))
      else
        :crypto.hash(:sha256, @protocol_name)
      end

    {h0, h0}
  end

  defp mix_hash(st, data) do
    %{st | h: :crypto.hash(:sha256, st.h <> data)}
  end

  defp mix_key(st, ikm) do
    {ck, k} = hkdf2(st.ck, ikm)
    %{st | ck: ck, cs: %{k: k, n: 0}}
  end

  defp encrypt_and_hash(%{cs: %{k: nil}} = st, plaintext) do
    # no key => plaintext pass-through
    st = mix_hash(st, plaintext)
    {plaintext, st}
  end

  defp encrypt_and_hash(st, plaintext) do
    {ciphertext, st2} = encrypt_with_ad(st, st.h, plaintext)
    st2 = mix_hash(st2, ciphertext)
    {ciphertext, st2}
  end

  defp decrypt_and_hash_exact(%{cs: %{k: nil}} = st, bin, n) do
    if byte_size(bin) < n, do: raise(ArgumentError, "truncated plaintext")
    <<pt::binary-size(n), rest::binary>> = bin
    st = mix_hash(st, pt)
    {pt, rest, st}
  end

  defp decrypt_and_hash_exact(st, bin, n) do
    # ciphertext includes tag
    need = n + @tag_len
    if byte_size(bin) < need, do: raise(ArgumentError, "truncated ciphertext")
    <<ct::binary-size(need), rest::binary>> = bin
    {pt, st2} = decrypt_with_ad(st, st.h, ct)
    if byte_size(pt) != n, do: raise(ArgumentError, "unexpected plaintext length")
    st2 = mix_hash(st2, ct)
    {pt, rest, st2}
  end

  defp decrypt_and_hash_to_end(%{cs: %{k: nil}} = st, bin) do
    st = mix_hash(st, bin)
    {bin, <<>>, st}
  end

  defp decrypt_and_hash_to_end(st, bin) do
    if byte_size(bin) < @tag_len, do: raise(ArgumentError, "truncated ciphertext")
    {pt, st2} = decrypt_with_ad(st, st.h, bin)
    st2 = mix_hash(st2, bin)
    {pt, <<>>, st2}
  end

  defp split(st) do
    {k1, k2} = hkdf2(st.ck, <<>>)
    {%{k: k1, n: 0}, %{k: k2, n: 0}}
  end

  # --- HKDF(sha256) producing 2 outputs ---
  defp hkdf2(chaining_key, ikm) do
    prk = :crypto.mac(:hmac, :sha256, chaining_key, ikm)
    t1 = :crypto.mac(:hmac, :sha256, prk, <<1>>)
    t2 = :crypto.mac(:hmac, :sha256, prk, t1 <> <<2>>)
    {t1, t2}
  end

  # --- AEAD ChaCha20-Poly1305 (handshake encrypt/decrypt) ---
  defp encrypt_with_ad(%{cs: %{k: key, n: n}} = st, ad, plaintext) do
    nonce = <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, ad, true)
    {ciphertext <> tag, %{st | cs: %{st.cs | n: n + 1}}}
  end

  defp decrypt_with_ad(%{cs: %{k: key, n: n}} = st, ad, ciphertext_and_tag) do
    nonce = <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
    ct_len = byte_size(ciphertext_and_tag) - @tag_len
    <<ct::binary-size(ct_len), tag::binary-size(@tag_len)>> = ciphertext_and_tag

    case :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ct, ad, tag, false) do
      :error -> raise(ArgumentError, "AEAD decrypt failed")
      pt -> {pt, %{st | cs: %{st.cs | n: n + 1}}}
    end
  end

  # --- DH (25519) ---
  defp dh_x25519(priv, pub) when is_binary(priv) and is_binary(pub) do
    :crypto.compute_key(:ecdh, pub, priv, :x25519)
  end

  # --- handshake payload ---
  defp make_handshake_payload(%Identity{} = identity, noise_static_pub32) when is_binary(noise_static_pub32) do
    identity_key_pb = PublicKeyPB.encode_public_key(:secp256k1, identity.pubkey_compressed)
    sig = Secp256k1.sign_bitcoin(identity.privkey, @sig_prefix <> noise_static_pub32)
    HandshakePayloadPB.encode(%{identity_key: identity_key_pb, identity_sig: sig})
  end

  defp verify_handshake_payload!(st, payload_bin, noise_static_pub32) do
    payload = HandshakePayloadPB.decode(payload_bin)
    {type, key_bytes} = PublicKeyPB.decode_public_key(payload.identity_key)

    ok =
      case type do
        :secp256k1 ->
          pub = Secp256k1.decompress_pubkey(key_bytes)
          Secp256k1.verify_bitcoin(pub, @sig_prefix <> noise_static_pub32, payload.identity_sig)

        other ->
          raise ArgumentError, "unsupported identity key type #{inspect(other)}"
      end

    if not ok, do: raise(ArgumentError, "invalid noise-libp2p static key signature")
    %{st | remote_identity_key: {type, key_bytes}}
  end
end
