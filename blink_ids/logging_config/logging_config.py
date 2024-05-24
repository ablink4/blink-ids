"""
Defines a common logger and configuration to use throughout the application
"""

import logging

# Set up the root logger
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Get the root logger
logger = logging.getLogger(__name__)