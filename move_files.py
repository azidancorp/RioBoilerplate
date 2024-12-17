import os
import shutil

source_dir = "c:/Users/Azidan/Desktop/AQL/RioBase/RioDocumentation/split_docs"
dest_dir = "c:/Users/Azidan/Desktop/AQL/RioBase/RioDocumentation"

# Move all files from source to destination
for file in os.listdir(source_dir):
    src_path = os.path.join(source_dir, file)
    dst_path = os.path.join(dest_dir, file)
    shutil.move(src_path, dst_path)
    print(f"Moved {file}")

# Remove the now-empty directory
os.rmdir(source_dir)
print("Moved all files and removed split_docs directory")
