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
  @u64_max 0xFFFF_FFFF_FFFF_FFFF
  @agent_log_path "/Users/timjester-pfadt/dev/ethereum/panacea/.cursor/debug.log"

  @type role :: :initiator | :responder

  @type cipher_state :: %{k: binary() | nil, n: non_neg_integer()}

  @type state :: %{
          role: role(),
          # symmetric state
          ck: binary(),
          h: binary(),
          cs: cipher_state(),
          hkdf_swap?: boolean(),
          nonce_be?: boolean(),
          # DH keys (25519)
          s_priv: binary(),
          s_pub: binary(),
          e_priv: binary() | nil,
          e_pub: binary() | nil,
          re: binary() | nil,
          rs: binary() | nil,
          # libp2p identity for signing/verification
          identity: Identity.t() | nil,
          remote_identity_key: {atom(), binary()} | nil,
          # NoiseExtensions: stream muxer negotiation (optional).
          local_stream_muxers: [binary()],
          remote_stream_muxers: [binary()],
          selected_stream_muxer: binary() | nil
        }

  @spec new(role(), Identity.t()) :: state()
  # Interop default (snow / rust-libp2p): initialize `ck`/`h` with the (unpadded) protocol name.
  # Note: our vendored libp2p Noise spec says to hash the protocol name, but the ecosystem
  # (snow-based implementations) uses the generic Noise rule, and the protocol name is exactly
  # 32 bytes, so there is no padding.
  def new(role, %Identity{} = identity) when role in [:initiator, :responder], do: new(role, identity, <<>>, false, false, false)

  @spec new(role(), Identity.t(), binary()) :: state()
  def new(role, %Identity{} = identity, prologue) when role in [:initiator, :responder] and is_binary(prologue),
    do: new(role, identity, prologue, false, false, false)

  @spec new(role(), Identity.t(), binary(), boolean()) :: state()
  def new(role, %Identity{} = identity, prologue, hash_protocol_name?)
      when role in [:initiator, :responder] and is_binary(prologue) and is_boolean(hash_protocol_name?) do
    new(role, identity, prologue, hash_protocol_name?, false, false)
  end

  @spec new(role(), Identity.t(), binary(), boolean(), boolean()) :: state()
  def new(role, %Identity{} = identity, prologue, hash_protocol_name?, hkdf_swap?)
      when role in [:initiator, :responder] and is_binary(prologue) and is_boolean(hash_protocol_name?) and is_boolean(hkdf_swap?) do
    new(role, identity, prologue, hash_protocol_name?, hkdf_swap?, false)
  end

  @spec new(role(), Identity.t(), binary(), boolean(), boolean(), boolean()) :: state()
  def new(role, %Identity{} = identity, prologue, hash_protocol_name?, hkdf_swap?, nonce_be?)
      when role in [:initiator, :responder] and is_binary(prologue) and is_boolean(hash_protocol_name?) and is_boolean(hkdf_swap?) and
             is_boolean(nonce_be?) do
    {s_pub, s_priv} = :crypto.generate_key(:ecdh, :x25519)
    {ck, h} = initialize_symmetric(hash_protocol_name?)

    st = %{
      role: role,
      ck: ck,
      h: h,
      cs: %{k: nil, n: 0},
      hkdf_swap?: hkdf_swap?,
      nonce_be?: nonce_be?,
      s_priv: s_priv,
      s_pub: s_pub,
      e_priv: nil,
      e_pub: nil,
      re: nil,
      rs: nil,
      identity: identity,
      remote_identity_key: nil,
      local_stream_muxers: ["/yamux/1.0.0"],
      remote_stream_muxers: [],
      selected_stream_muxer: nil
    }

    # Snow mixes the prologue into `h` unconditionally (even if empty).
    mix_hash(st, prologue)
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
    # Snow always "encrypt_and_mix_hash(payload)" even if payload is empty.
    # In XX, msg1 payload is empty, so this is equivalent to MixHash("").
    st = mix_hash(st, <<>>)
    {e_pub, st}
  end

  @doc false
  @spec __diag_try_decrypt_msg2_static__(state(), binary()) ::
          [%{hash_protocol_name?: boolean(), hkdf_swap?: boolean(), nonce_be?: boolean(), rs_pub_prefix_hex: binary()}]
  def __diag_try_decrypt_msg2_static__(%{role: :initiator, e_priv: e_priv, e_pub: e_pub, identity: %Identity{} = id}, msg2)
      when is_binary(msg2) do
    if not is_binary(e_priv) or not is_binary(e_pub) or byte_size(e_pub) != 32 do
      []
    else
      prologues = [
        <<>>,
        "libp2p",
        "libp2p-noise",
        "/noise",
        "/multistream/1.0.0",
        @sig_prefix
      ]

      case msg2 do
        <<re::binary-size(32), rest::binary>> when byte_size(rest) >= 48 ->
          <<ct_s::binary-size(48), _::binary>> = rest

          for prologue <- prologues,
              hash_protocol_name? <- [false, true],
              hkdf_swap? <- [false, true],
              nonce_be? <- [false, true],
              reduce: [] do
            acc ->
              st0 = new(:initiator, id, prologue, hash_protocol_name?, hkdf_swap?, nonce_be?)
              # Replay initiator msg1 transcript with the *real* ephemeral keypair used on-wire.
              st0 = %{st0 | e_priv: e_priv, e_pub: e_pub}
              st0 = mix_hash(st0, e_pub)
              st0 = %{st0 | re: re}
              st0 = mix_hash(st0, re)
              st0 = mix_key(st0, dh_x25519(e_priv, re))

              try do
                {rs_pub, _st1} = decrypt_with_ad(st0, st0.h, ct_s)

                [
                  %{
                    prologue_len: byte_size(prologue),
                    hash_protocol_name?: hash_protocol_name?,
                    hkdf_swap?: hkdf_swap?,
                    nonce_be?: nonce_be?,
                    rs_pub_prefix_hex:
                      Base.encode16(binary_part(rs_pub, 0, min(8, byte_size(rs_pub))), case: :lower)
                  }
                  | acc
                ]
              rescue
                _ ->
                  acc
              end
          end

        _ ->
          []
      end
    end
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
    # Snow mixes in the (empty) payload of msg1.
    st = mix_hash(st, <<>>)

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
    if n > @u64_max, do: raise(ArgumentError, "nonce counter exhausted")
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
    if n > @u64_max, do: raise(ArgumentError, "nonce counter exhausted")
    nonce = <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
    ct_len = byte_size(ciphertext_and_tag) - @tag_len
    <<ct::binary-size(ct_len), tag::binary-size(@tag_len)>> = ciphertext_and_tag

    case :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, ct, ad, tag, false) do
      :error -> raise(ArgumentError, "AEAD decrypt failed")
      pt -> {pt, %{cs | n: n + 1}}
    end
  end

  # --- symmetric state helpers (Noise Framework semantics) ---
  defp initialize_symmetric(hash_protocol_name?) do
    # NOTE: libp2p noise spec states the HandshakeState is initialized with the
    # hash of the Noise protocol name (not the padded name per generic Noise).
    #
    # We keep the legacy padded behavior behind `hash_protocol_name? == false`
    # for interoperability experiments.
    h0 =
      if hash_protocol_name? do
        :crypto.hash(:sha256, @protocol_name)
      else
        # legacy (generic Noise): if protocol name shorter than hashlen, pad with zeros; else hash.
        if byte_size(@protocol_name) <= 32 do
          @protocol_name <> :binary.copy(<<0>>, 32 - byte_size(@protocol_name))
        else
          :crypto.hash(:sha256, @protocol_name)
        end
      end

    {h0, h0}
  end

  defp mix_hash(st, data) do
    %{st | h: :crypto.hash(:sha256, st.h <> data)}
  end

  defp mix_key(st, ikm) do
    {t1, t2} = hkdf2(st.ck, ikm)
    {ck, k} = if(st.hkdf_swap?, do: {t2, t1}, else: {t1, t2})
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
    # region agent log
    agent_log(
      "P",
      "third_party/libp2p_elixir/lib/libp2p/noise.ex:decrypt_and_hash_exact/3",
      "handshake decrypt attempt",
      %{
        n: n,
        ct_bytes: byte_size(ct),
        cs_n: st.cs.n,
        hkdf_swap: st.hkdf_swap?,
        nonce_be: Map.get(st, :nonce_be?, false),
        h8:
          Base.encode16(binary_part(st.h, 0, min(8, byte_size(st.h))), case: :lower),
        ck8:
          Base.encode16(binary_part(st.ck, 0, min(8, byte_size(st.ck))), case: :lower),
        k8:
          if(is_binary(st.cs.k),
            do: Base.encode16(binary_part(st.cs.k, 0, min(8, byte_size(st.cs.k))), case: :lower),
            else: ""
          )
      }
    )
    # endregion agent log

    {pt, st2} =
      try do
        decrypt_with_ad(st, st.h, ct)
      rescue
        e in ArgumentError ->
          # region agent log
          agent_log(
            "P",
            "third_party/libp2p_elixir/lib/libp2p/noise.ex:decrypt_and_hash_exact/3",
            "handshake decrypt failed",
            %{
              n: n,
              ct_bytes: byte_size(ct),
              cs_n: st.cs.n,
              hkdf_swap: st.hkdf_swap?,
              nonce_be: Map.get(st, :nonce_be?, false),
              h8:
                Base.encode16(binary_part(st.h, 0, min(8, byte_size(st.h))), case: :lower),
              ck8:
                Base.encode16(binary_part(st.ck, 0, min(8, byte_size(st.ck))), case: :lower),
              k8:
                if(is_binary(st.cs.k),
                  do: Base.encode16(binary_part(st.cs.k, 0, min(8, byte_size(st.cs.k))), case: :lower),
                  else: ""
                ),
              error: Exception.message(e)
            }
          )
          # endregion agent log

          reraise e, __STACKTRACE__
      end
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

  defp agent_log(hypothesis_id, location, message, data) when is_map(data) do
    payload =
      %{
        sessionId: "debug-session",
        runId: "pre-fix",
        hypothesisId: hypothesis_id,
        location: location,
        message: message,
        data: data,
        timestamp: System.system_time(:millisecond)
      }
      |> agent_json()

    File.write!(@agent_log_path, payload <> "\n", [:append])
  rescue
    _ -> :ok
  end

  defp agent_json(map) when is_map(map) do
    "{" <>
      (map
       |> Enum.map(fn {k, v} -> agent_json_string(to_string(k)) <> ":" <> agent_json(v) end)
       |> Enum.join(",")) <> "}"
  end

  defp agent_json(list) when is_list(list) do
    "[" <> (list |> Enum.map(&agent_json/1) |> Enum.join(",")) <> "]"
  end

  defp agent_json(bin) when is_binary(bin), do: agent_json_string(bin)
  defp agent_json(i) when is_integer(i), do: Integer.to_string(i)
  defp agent_json(true), do: "true"
  defp agent_json(false), do: "false"
  defp agent_json(nil), do: "null"
  defp agent_json(other), do: agent_json_string(inspect(other, limit: 50))

  defp agent_json_string(s) when is_binary(s) do
    "\"" <>
      (s
       |> String.replace("\\", "\\\\")
       |> String.replace("\"", "\\\"")
       |> String.replace("\n", "\\n")
       |> String.replace("\r", "\\r")
       |> String.replace("\t", "\\t")) <> "\""
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

  # --- internal helpers for tests ---
  @doc false
  @spec __hkdf2__(binary(), binary()) :: {binary(), binary()}
  def __hkdf2__(chaining_key, ikm) when is_binary(chaining_key) and is_binary(ikm), do: hkdf2(chaining_key, ikm)

  @doc false
  @spec __nonce12__(non_neg_integer(), :little | :big) :: <<_::96>>
  def __nonce12__(n, endian) when is_integer(n) and n >= 0 and endian in [:little, :big] do
    case endian do
      :little -> <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
      :big -> <<0::unsigned-big-integer-size(32), n::unsigned-big-integer-size(64)>>
    end
  end

  @doc false
  @spec __initiator_with_ephemeral__(Identity.t(), binary(), boolean(), boolean(), boolean(), binary(), binary()) :: state()
  def __initiator_with_ephemeral__(%Identity{} = identity, prologue, hash_protocol_name?, hkdf_swap?, nonce_be?, e_pub, e_priv)
      when is_binary(prologue) and is_boolean(hash_protocol_name?) and is_boolean(hkdf_swap?) and is_boolean(nonce_be?) and
             is_binary(e_pub) and is_binary(e_priv) and byte_size(e_pub) == 32 and byte_size(e_priv) == 32 do
    st = new(:initiator, identity, prologue, hash_protocol_name?, hkdf_swap?, nonce_be?)
    st = %{st | e_pub: e_pub, e_priv: e_priv}
    st = mix_hash(st, e_pub)
    mix_hash(st, <<>>)
  end

  # --- AEAD ChaCha20-Poly1305 (handshake encrypt/decrypt) ---
  defp encrypt_with_ad(%{cs: %{k: key, n: n}} = st, ad, plaintext) do
    if n > @u64_max, do: raise(ArgumentError, "nonce counter exhausted")
    if not is_binary(key) or byte_size(key) != 32, do: raise(ArgumentError, "bad chacha20 key length: #{inspect(byte_size(key))}")
    nonce =
      if st.nonce_be? do
        <<0::unsigned-big-integer-size(32), n::unsigned-big-integer-size(64)>>
      else
        <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
      end
    if byte_size(nonce) != 12, do: raise(ArgumentError, "bad chacha20 nonce length: #{inspect(byte_size(nonce))}")
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, ad, true)
    {ciphertext <> tag, %{st | cs: %{st.cs | n: n + 1}}}
  end

  defp decrypt_with_ad(%{cs: %{k: key, n: n}} = st, ad, ciphertext_and_tag) do
    if n > @u64_max, do: raise(ArgumentError, "nonce counter exhausted")
    if not is_binary(key) or byte_size(key) != 32, do: raise(ArgumentError, "bad chacha20 key length: #{inspect(byte_size(key))}")
    nonce =
      if st.nonce_be? do
        <<0::unsigned-big-integer-size(32), n::unsigned-big-integer-size(64)>>
      else
        <<0::unsigned-little-integer-size(32), n::unsigned-little-integer-size(64)>>
      end
    if byte_size(nonce) != 12, do: raise(ArgumentError, "bad chacha20 nonce length: #{inspect(byte_size(nonce))}")
    ct_len = byte_size(ciphertext_and_tag) - @tag_len
    <<ct::binary-size(ct_len), tag::binary-size(@tag_len)>> = ciphertext_and_tag
    if byte_size(tag) != @tag_len, do: raise(ArgumentError, "bad chacha20 tag length: #{inspect(byte_size(tag))}")

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
    # Advertise supported stream muxers (NoiseExtensions.stream_muxers) per spec.
    ext = HandshakePayloadPB.encode_extensions(%{stream_muxers: ["/yamux/1.0.0"]})
    HandshakePayloadPB.encode(%{identity_key: identity_key_pb, identity_sig: sig, extensions: ext})
  end

  defp verify_handshake_payload!(st, payload_bin, noise_static_pub32) do
    {type, key_bytes, remote_muxers} = verify_handshake_payload(payload_bin, noise_static_pub32)
    st = %{st | remote_identity_key: {type, key_bytes}, remote_stream_muxers: remote_muxers}
    select_stream_muxer(st)
  end

  defp verify_handshake_payload(payload_bin, noise_static_pub32) do
    payload = HandshakePayloadPB.decode(payload_bin)
    {type, key_bytes} = PublicKeyPB.decode_public_key(payload.identity_key)
    remote_muxers =
      case HandshakePayloadPB.decode_extensions(payload.extensions) do
        %{stream_muxers: muxers} when is_list(muxers) -> muxers
        _ -> []
      end

    ok =
      case type do
        :secp256k1 ->
          pub = Secp256k1.decompress_pubkey(key_bytes)
          Secp256k1.verify_bitcoin(pub, @sig_prefix <> noise_static_pub32, payload.identity_sig)

        other ->
          raise ArgumentError, "unsupported identity key type #{inspect(other)}"
      end

    if not ok, do: raise(ArgumentError, "invalid noise-libp2p static key signature")
    {type, key_bytes, remote_muxers}
  end

  @doc false
  @spec __verify_handshake_payload__(binary(), binary()) :: {atom(), binary()}
  def __verify_handshake_payload__(payload_bin, noise_static_pub32)
      when is_binary(payload_bin) and is_binary(noise_static_pub32) and byte_size(noise_static_pub32) == 32 do
    verify_handshake_payload(payload_bin, noise_static_pub32)
  end

  defp select_stream_muxer(%{selected_stream_muxer: sel} = st) when is_binary(sel), do: st

  defp select_stream_muxer(%{role: :initiator} = st) do
    # Initiator ordering determines selection.
    sel = Enum.find(st.local_stream_muxers, fn m -> is_binary(m) and m in st.remote_stream_muxers end)

    cond do
      st.remote_stream_muxers == [] ->
        # Peer did not advertise muxers via NoiseExtensions; fall back to MSS muxer negotiation.
        st

      is_binary(sel) ->
        %{st | selected_stream_muxer: sel}

      true ->
        raise(ArgumentError, "no common stream muxer in noise extensions")
    end
  end

  defp select_stream_muxer(%{role: :responder} = st) do
    # Responder must respect initiator ordering (which we receive as `remote_stream_muxers`).
    sel = Enum.find(st.remote_stream_muxers, fn m -> is_binary(m) and m in st.local_stream_muxers end)

    cond do
      st.remote_stream_muxers == [] ->
        st

      is_binary(sel) ->
        %{st | selected_stream_muxer: sel}

      true ->
        raise(ArgumentError, "no common stream muxer in noise extensions")
    end
  end
end
