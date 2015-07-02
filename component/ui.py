import os
import sys

if os.name == 'nt':
    from component._ui_win import UI  
elif sys.platform == "darwin":
    from component._ui_mac import UI  