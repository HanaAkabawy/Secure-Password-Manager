import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pwm.dh_export import (
    generate_dh_params, generate_dh_keypair,
    build_export_package, consume_export_package
)
from pwm.vault import create_vault, add_credential, list_credentials
from pwm._mock_elgamal import generate_keypair

def test_export_package():
    print("Testing export/import package...")
    
    q, alpha = generate_dh_params(512)
    
    sender_vault_path = "sender_test_vault.json"
    receiver_vault_path = "receiver_test_vault.json"
    
    # Cleanup old test files
    if os.path.exists(sender_vault_path): os.remove(sender_vault_path)
    if os.path.exists(receiver_vault_path): os.remove(receiver_vault_path)
    
    # Create sender vault
    create_vault(sender_vault_path, "sender_master")
    add_credential(sender_vault_path, "sender_master", "example.com", "user1", "pass1")
    add_credential(sender_vault_path, "sender_master", "test.com", "user2", "pass2")
    
    # ElGamal keys (Mock)
    sender_pub, sender_priv = generate_keypair()
    receiver_pub, receiver_priv = generate_keypair()
    
    # DH keypairs
    sender_dh_priv, sender_dh_pub = generate_dh_keypair(q, alpha)
    receiver_dh_priv, receiver_dh_pub = generate_dh_keypair(q, alpha)
    
    # Build package
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
    
    # Consume package
    consume_export_package(
        package=pkg,
        my_dh_priv=receiver_dh_priv,
        peer_elgamal_pub=sender_pub,
        new_master_password="receiver_master",
        output_vault_path=receiver_vault_path,
        my_elgamal_priv=receiver_priv,
        q=q
    )
    
    # Verify received vault
    creds = list_credentials(receiver_vault_path, "receiver_master")
    assert len(creds) == 2
    assert creds[0]["website"] == "example.com"
    assert creds[0]["password"] == "pass1"
    assert creds[1]["website"] == "test.com"
    assert creds[1]["password"] == "pass2"
    
    # Cleanup
    os.remove(sender_vault_path)
    os.remove(receiver_vault_path)
    print("Export/import test passed!")

if __name__ == "__main__":
    test_export_package()

