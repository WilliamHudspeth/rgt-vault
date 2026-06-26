import os

def test_setup():
    print("Creating symlink...")
    if not os.path.exists("rgt_vault"):
        os.symlink("python", "rgt_vault")
        print("Symlink created!")
    else:
        print("Symlink already exists!")
