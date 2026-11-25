import tkinter as tk
from app.ui.workbench import PacketWorkbenchApp

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketWorkbenchApp(root)
    root.mainloop()
