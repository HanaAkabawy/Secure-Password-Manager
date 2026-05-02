import os
import sys
import copy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair,
    build_export_package, consume_export_package,
    SignatureVerificationError, save_dh_params
)
from pwm.vault import create_vault, add_credential
from pwm._mock_elgamal import generate_keypair

def test_tamper_package():
    print("Testing tamper package...")
    q, alpha = generate_dh_params(512)
    save_dh_params(q, alpha, "pwm/dh_params.json")
    
    sender_vault_path = "sender_test_vault2.json"
    receiver_vault_path = "receiver_test_vault2.json"
    
    # Cleanup old test files
    if os.path.exists(sender_vault_path): os.remove(sender_vault_path)
    if os.path.exists(receiver_vault_path): os.remove(receiver_vault_path)
    
    create_vault(sender_vault_path, "sender_master")
    add_credential(sender_vault_path, "sender_master", "example.com", "user1", "pass1")
    
    sender_pub, sender_priv = generate_keypair()
    receiver_pub, receiver_priv = generate_keypair()
    sender_dh_priv, sender_dh_pub = generate_dh_keypair(q, alpha)
    receiver_dh_priv, receiver_dh_pub = generate_dh_keypair(q, alpha)
    
    pkg = build_export_package(
        vault_path=sender_vault_path,
        master_password="sender_master",
        my_dh_priv=sender_dh_priv,
        my_dh_pub=sender_dh_pub,
        peer_dh_pub=receiver_dh_pub,
        my_elgamal_priv=sender_priv,
        my_elgamal_pub=sender_pub,
        q=q,
        alpha=alpha
    )
    
    # Tamper the package (change last byte of ciphertext)
    pkg_tampered = copy.deepcopy(pkg)
    ct = bytearray.fromhex(pkg_tampered["session_ciphertext_hex"])
    ct[-1] ^= 0x01
    pkg_tampered["session_ciphertext_hex"] = ct.hex()
    
    try:
        consume_export_package(
            package=pkg_tampered,
            my_dh_priv=receiver_dh_priv,
            peer_elgamal_pub=sender_pub,
            new_master_password="receiver_master",
            output_vault_path=receiver_vault_path,
            my_elgamal_priv=receiver_priv,
            q=q,
            alpha=alpha
        )
        assert False, "Tampered package should have thrown an exception!"
    except SignatureVerificationError:
        print("Tamper test passed! Exception was raised correctly.")
    
    # Cleanup
    os.remove(sender_vault_path)
    if os.path.exists(receiver_vault_path):
        os.remove(receiver_vault_path)

if __name__ == "__main__":
    test_tamper_package()



