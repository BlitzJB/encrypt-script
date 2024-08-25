import unittest
import os
import tempfile
from encrypt import get_key, calculate_checksum, process_file

class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.test_password = "testpassword123"
        self.test_key = get_key(self.test_password)
        self.test_data = b"This is test data"
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_get_key(self):
        key = get_key(self.test_password)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 44)  # Base64 encoded 32-byte key

    def test_calculate_checksum(self):
        checksum = calculate_checksum(self.test_data)
        self.assertIsInstance(checksum, str)
        self.assertEqual(len(checksum), 32)  # MD5 hash is 32 characters long

    def test_process_file_encryption(self):
        test_file_path = os.path.join(self.temp_dir, "test_file.txt")
        with open(test_file_path, "wb") as f:
            f.write(self.test_data)

        success, metadata = process_file(test_file_path, self.test_key, encrypt=True)
        self.assertTrue(success)
        self.assertIsInstance(metadata, dict)
        self.assertEqual(len(os.listdir(self.temp_dir)), 1)
        encrypted_file = os.listdir(self.temp_dir)[0]
        self.assertTrue(encrypted_file.endswith('.enc'))

    def test_process_file_decryption(self):
        # encryption
        test_file_path = os.path.join(self.temp_dir, "test_file.txt")
        with open(test_file_path, "wb") as f:
            f.write(self.test_data)
        success, metadata = process_file(test_file_path, self.test_key, encrypt=True)
        encrypted_file = os.listdir(self.temp_dir)[0]

        # decryption
        encrypted_file_path = os.path.join(self.temp_dir, encrypted_file)
        success, _ = process_file(encrypted_file_path, self.test_key, encrypt=False, all_metadata=metadata)
        self.assertTrue(success)
        decrypted_file = os.listdir(self.temp_dir)[0]
        self.assertEqual(decrypted_file, "test_file.txt")

        with open(os.path.join(self.temp_dir, decrypted_file), "rb") as f:
            decrypted_data = f.read()
        self.assertEqual(decrypted_data, self.test_data)

if __name__ == '__main__':
    unittest.main()