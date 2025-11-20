def encrypt_data(plaintext: bytes, iterations: int = 100000) -> bytes:
    import os
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(os.getenv('ENC0').encode("utf-8"))
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # No associated data
    return salt + nonce + ciphertext

def save_video(out_path:str, images, fps, metadata=None):
    import io, av
    with io.BytesIO() as binary_obj:
        with av.open(binary_obj, mode='w', format="mp4") as output:
            # Add metadata before writing any streams
            if metadata is not None:
                for key, value in metadata.items():
                    output.metadata[key] = value

            stream = output.add_stream("h264", rate=fps)
            stream.width = images.shape[2]
            stream.height = images.shape[1]
            stream.pix_fmt = "yuv420p"
            
            # Encode video
            for frame in images:
                img = (frame * 255).clamp(0, 255).byte().cpu().numpy() # shape: (H, W, 3)
                frame = av.VideoFrame.from_ndarray(img, format='rgb24')
                for packet in stream.encode(frame):
                    output.mux(packet)
        
            # Flush video
            for packet in stream.encode():
                output.mux(packet)
        
        with open(out_path, 'wb') as f:
            f.write(encrypt_data(binary_obj.getvalue()))

    return out_path

def save_image(out_path:str, images, metadata=None):
    import io, json
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo
    img = (images[0] * 255).clamp(0, 255).byte().cpu().numpy()
    with io.BytesIO() as binary_obj:
        img = Image.fromarray(img)
        if metadata:
            meta= PngInfo()
            meta.add_text("parameters", json.dumps(metadata))
            img.save(binary_obj, format="PNG", pnginfo=meta)
        else:
            img.save(binary_obj, format="PNG")
        
        with open(out_path, 'wb') as f:
            f.write(encrypt_data(binary_obj.getvalue()))

    return out_path

def load_image(zip_path:str, file_name:str):
    import pyzipper, torch, os
    import numpy as np
    from PIL import Image
    with pyzipper.AESZipFile(zip_path) as myzip:
        with myzip.open(file_name, pwd=os.getenv('ENC0').encode("utf-8")) as myfile:
            image = Image.open(myfile)
            image = image.convert("RGB")
            image = np.array(image).astype(np.float32) / 255.0
            image = torch.from_numpy(image)[None,]
            return image