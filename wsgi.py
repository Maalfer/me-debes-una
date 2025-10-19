import sys
import os
from pathlib import Path

# Añadir el directorio de la aplicación al path
basedir = Path(__file__).parent.absolute()
sys.path.insert(0, str(basedir))

# Importar la aplicación
from app import app as application
