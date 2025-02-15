import os
import shutil

'''
remove .exe files from all subdirectories
'''

def main():
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith('.exe'):
                os.remove(os.path.join(root, file))
                print('Removed:', os.path.join(root, file))

if __name__ == '__main__':
    main()