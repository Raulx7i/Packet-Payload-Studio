import tkinter as tk
from app.ui.workbench import PacketWorkbenchApp


def main():
    root = tk.Tk()
    PacketWorkbenchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
