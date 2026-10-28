# Used in HTB Academy pickles and steg AI module - AI Data Attacks

import struct

import torch


def encode_lsb(
    tensor_orig: torch.Tensor,
    data_bytes: bytes,
    num_lsb: int,
) -> torch.Tensor:
    """Encode bytes into a float32 tensor's least significant bits.

    Prepends the payload length as a 4-byte unsigned big-endian integer.

    Args:
        tensor_orig: The original float32 tensor.
        data_bytes: The byte string to encode.
        num_lsb: Number of least significant bits to use per float (1–8).

    Returns:
        A detached copy of the tensor containing the embedded data.

    Raises:
        TypeError: If tensor_orig is not a float32 tensor.
        ValueError: If num_lsb is outside the range 1–8.
        ValueError: If the tensor cannot hold the header and payload.
    """
    if tensor_orig.dtype != torch.float32:
        raise TypeError("Tensor must be float32.")

    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be 1–8. More bits increase distortion.")

    tensor = tensor_orig.detach().clone().contiguous()
    tensor_flat = tensor.view(-1)
    n_elements = tensor.numel()

    # Prepend the payload length as a 4-byte unsigned integer.
    data_to_embed = struct.pack(">I", len(data_bytes)) + data_bytes

    total_bits_needed = len(data_to_embed) * 8
    capacity_bits = n_elements * num_lsb

    if total_bits_needed > capacity_bits:
        required_elements = (total_bits_needed + num_lsb - 1) // num_lsb

        raise ValueError(
            f"Tensor too small: needs {total_bits_needed} bits, "
            f"but capacity is {capacity_bits} bits. "
            f"Required elements: {required_elements}, "
            f"available: {n_elements}."
        )

    data_iter = iter(data_to_embed)
    current_byte = next(data_iter, None)
    bit_index_in_byte = 7
    element_index = 0
    bits_embedded = 0
    mask = (1 << num_lsb) - 1

    while bits_embedded < total_bits_needed:
        original_float = tensor_flat[element_index].item()
        packed_float = struct.pack(">f", original_float)
        int_representation = struct.unpack(">I", packed_float)[0]

        data_bits_for_float = 0

        for i in range(num_lsb):
            if current_byte is None:
                break

            data_bit = (current_byte >> bit_index_in_byte) & 1
            data_bits_for_float |= data_bit << (num_lsb - 1 - i)

            bit_index_in_byte -= 1
            bits_embedded += 1

            if bit_index_in_byte < 0:
                current_byte = next(data_iter, None)
                bit_index_in_byte = 7

            if bits_embedded >= total_bits_needed:
                break

        # Replace the selected LSBs with the payload bits.
        cleared_int = int_representation & ~mask
        new_int_representation = cleared_int | data_bits_for_float

        new_packed_float = struct.pack(">I", new_int_representation)
        new_float = struct.unpack(">f", new_packed_float)[0]

        tensor_flat[element_index] = new_float
        element_index += 1

    print(
        f"Encoded {bits_embedded} bits into {element_index} elements "
        f"using {num_lsb} LSB(s) per element."
    )

    return tensor


def decode_lsb(
    tensor_modified: torch.Tensor,
    num_lsb: int,
) -> bytes:
    """Decode bytes hidden in a float32 tensor's least significant bits.

    Expects data encoded by encode_lsb, with a 4-byte unsigned
    big-endian payload length followed by the payload.

    Args:
        tensor_modified: The float32 tensor containing the hidden data.
        num_lsb: Number of least significant bits used per float (1–8).

    Returns:
        The decoded byte string.

    Raises:
        TypeError: If tensor_modified is not a float32 tensor.
        ValueError: If num_lsb is outside the range 1–8.
        ValueError: If the tensor cannot hold the declared header or payload.
    """
    if tensor_modified.dtype != torch.float32:
        raise TypeError("Tensor must be float32.")

    if not 1 <= num_lsb <= 8:
        raise ValueError("num_lsb must be 1–8.")

    tensor_flat = tensor_modified.flatten()
    n_elements = tensor_flat.numel()
    capacity_bits = n_elements * num_lsb
    mask = (1 << num_lsb) - 1

    element_index = 0
    bits_read = 0
    bits_remaining = 0
    lsb_data = 0

    def get_bits(count: int) -> list[int]:
        """Read bits while retaining unused bits in the current element."""
        nonlocal element_index, bits_read, bits_remaining, lsb_data

        available_bits = capacity_bits - bits_read

        if count > available_bits:
            raise ValueError(
                f"Insufficient tensor capacity: requested {count} bits, "
                f"but only {available_bits} bits remain."
            )

        bits = []

        for _ in range(count):
            if bits_remaining == 0:
                current_float = tensor_flat[element_index].item()
                packed_float = struct.pack(">f", current_float)
                int_representation = struct.unpack(">I", packed_float)[0]

                lsb_data = int_representation & mask
                bits_remaining = num_lsb
                element_index += 1

            bits_remaining -= 1
            bit = (lsb_data >> bits_remaining) & 1
            bits.append(bit)
            bits_read += 1

        return bits

    # Read the 32-bit unsigned payload length.
    try:
        length_bits = get_bits(32)
    except ValueError as exc:
        raise ValueError(
            f"Failed to decode payload length: {exc}"
        ) from exc

    payload_len_bytes = 0

    for bit in length_bits:
        payload_len_bytes = (payload_len_bytes << 1) | bit

    # Validate capacity before allocating storage for the payload.
    payload_bits_needed = payload_len_bytes * 8
    available_bits = capacity_bits - bits_read

    if payload_bits_needed > available_bits:
        raise ValueError(
            f"Failed to decode payload (length: {payload_len_bytes} bytes): "
            f"needs {payload_bits_needed} bits, "
            f"but only {available_bits} bits remain."
        )

    # Assemble the payload one byte at a time.
    decoded_bytes = bytearray()

    for _ in range(payload_len_bytes):
        byte_value = 0

        for bit in get_bits(8):
            byte_value = (byte_value << 1) | bit

        decoded_bytes.append(byte_value)

    print(
        f"Decoded {len(decoded_bytes)} bytes. "
        f"Used {element_index} tensor elements "
        f"with {num_lsb} LSB(s) per element."
    )

    return bytes(decoded_bytes)


if __name__ == "__main__":
    original = torch.randn(1_000, dtype=torch.float32)
    message = b"Hello, world!"
    num_lsb = 3

    encoded = encode_lsb(original, message, num_lsb)
    decoded = decode_lsb(encoded, num_lsb)

    assert decoded == message
    print(decoded)
