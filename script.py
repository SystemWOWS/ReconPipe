import shutil, os

# Copy final files to output dir for sharing
os.makedirs('output', exist_ok=True)
shutil.copy('/home/user/reconpipe/reconpipe.py', 'output/reconpipe.py')
shutil.copy('/home/user/reconpipe/install.sh', 'output/install.sh')
shutil.copy('/home/user/reconpipe/README.md', 'output/README.md')
shutil.copy('/home/user/reconpipe/requirements.txt', 'output/requirements.txt')

print("Files ready:")
for f in ['reconpipe.py','install.sh','README.md','requirements.txt']:
    size = os.path.getsize(f'output/{f}')
    print(f"  {f:<22} {size:,} bytes")