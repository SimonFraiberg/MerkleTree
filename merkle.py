import hashlib
import base64 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
class MerkleTree:
    def __init__(self):
        self.leaves = []
        self.root = None

    def hash_data(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_tree(self, leaves):
        tree_length = len(leaves)
        if tree_length == 1:
            return leaves[0]
  
        parents = []
        for i in range(0, tree_length, 2):
            if (tree_length % 2 == 1 and tree_length - 1 == i):   
                parents.append(leaves[i])
            else:  
                combined_hash = self.hash_data(leaves[i] + leaves[i + 1])
                #print(str(i) + ","+ str(i + 1) + " :" + str(combined_hash)) 
                parents.append(combined_hash)

        return self.build_tree(parents)
    


    def proof_of_inclusion(self,index):
        current_level = self.leaves
        proof = []
        while len(current_level) > 1:
            if (not (index == len(self.leaves) - 1 and len(self.leaves) % 2 == 1)):
                if (index % 2 == 1):
                    proof.append('0' + current_level[index - 1])
                else:
                    proof.append('1' + current_level[index + 1])
            next_level = []
            for i in range(0, len(current_level), 2):
                if (len(current_level) % 2 == 1 and len(current_level) - 1 == i):   
                    next_level.append(current_level[i])
                else:  
                    combined_hash = self.hash_data(current_level[i] + current_level[i + 1])
                    next_level.append(combined_hash)

            current_level = next_level
            index //= 2
        return proof
    
    def proof_check(self,value, proof):
        value_hash= self.hash_data(value)
        root, *rest_proof = proof
        for hash in rest_proof:
            if(hash[0] == "1"):
                value_hash = self.hash_data(value_hash + hash[1:])
            else:
                value_hash = self.hash_data(hash[1:] + value_hash)
            
        if (value_hash == root):
            return True
        return False
    

    def add_leaf(self, data):
        new_leaf = self.hash_data(data)
        self.leaves.append(new_leaf)
    

    def get_root(self):
        if (self.leaves):
            self.root = self.build_tree(self.leaves)
        return  self.root
    
    def print_tree(self):
        print("root:" + str(self.root))
        print("leafs:" + str(self.leaves))

    def sign_root_rsa(self, key):
        private_key = serialization.load_pem_private_key(
            key.encode(),
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign(
            self.get_root().encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature_bytes = base64.b64encode(signature)
        return signature_bytes.decode("ascii")
    
    def verifiy_root_rsa(self, key, signature, text):
        try:
            public_key = serialization.load_pem_public_key(
                key.encode(),  
                backend=default_backend()
            )
            # Decode the base64 encoded signature
            decoded_signature = base64.b64decode(signature)
            public_key.verify(
                decoded_signature,
                text.encode(),  # Ensure text is bytes
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return (private_pem.decode('utf-8'),public_pem.decode('utf-8'))

def read_multiline_input_key():
    lines = []
    while True:
        line = input()
        if "END" in line:
            lines.append(line)
            input()
            break
        lines.append(line)
    
    return "\n".join(lines)

def read_multiline_input_signature():
    lines = []
    while True:
        line = input()
        if "==" in line:
            lines.append(line)
            break
        lines.append(line)
    
    return "\n".join(lines)


def main():
    merkle_tree = MerkleTree()
    while True:
        user_input = input()
        if user_input.startswith("6"):
            rest_user_input = read_multiline_input_key()
            user_input = user_input + "\n" + rest_user_input
        if user_input.startswith("7"):
            rest_user_input = read_multiline_input_key()
            user_input = user_input + "\n" + rest_user_input
            user_input = user_input + " "  + read_multiline_input_signature()
            user_input = user_input + " " + input()
        parts = user_input.split()
        if (len(parts) == 0):
            continue
        option = parts[0]
        if (option == "1"):
            if len(parts) != 2:
                print(" ")
                continue
            merkle_tree.add_leaf(parts[1])
        if (option == "2"):
            if len(parts) != 1:
                print(" ")
                continue
            root = merkle_tree.get_root()
            if (root):
                print(root)
            else:
                print(" ")
        if (option == "3"):
            if len(parts) != 2:
                print(" ")
                continue
            proof = merkle_tree.proof_of_inclusion(int(parts[1]))
            if (len(proof) == 0):
                print(" ")
            else:
               root = merkle_tree.get_root()
               if (root):
                   print(root)
               for hash in proof:
                   print(hash)
        if (option == "4"):
            if len(parts) < 3:
                print(" ")
                continue
            option, value, *proof = parts
            if(merkle_tree.proof_check(value, proof)):
                print("True")
            else:
                print("False")
        if (option == "5"):
            if len(parts) != 1:
                print(" ")
                continue    
            private_key,public_key = generate_rsa_keys()
            print(private_key)
            print(public_key)

        if (option == "6"):
            if len(parts) < 2:
                print(" ")
                continue   
            key = user_input.split(" ",1)[1]
            print(key)
            signature = merkle_tree.sign_root_rsa(key)
            print(signature)
        if (option == "7"):
          
            args = user_input.split(" ",1)[1]
            key_split = args.split("-----END PUBLIC KEY-----",1)
            key = key_split[0]+ "-----END PUBLIC KEY-----\n"
            rest_args = (key_split[1].split(" ",1)[1].split("=="))
            rest_args[0] = rest_args[0] + "=="

            result = merkle_tree.verifiy_root_rsa(key,rest_args[0].strip(),rest_args[1].strip())
            if result:
                print("True")
            else:
                print("False")
        

       

if __name__ == "__main__":
    main()