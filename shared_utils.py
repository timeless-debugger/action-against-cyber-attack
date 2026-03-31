import csv
from datetime import datetime
import os

# ============================================
# SHARED CONFIGURATION
# ============================================
LOG_DIRECTORY = "logs"

# Create logs directory if it doesn't exist
if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)


# ============================================
# LOGGING FUNCTIONS
# ============================================
def save_to_csv(filename, data, fieldnames):
    """
    Save data to CSV file
    
    Args:
        filename: Name of the CSV file
        data: List of dictionaries to save
        fieldnames: List of column names
    """
    filepath = os.path.join(LOG_DIRECTORY, filename)
    
    try:
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        return True, filepath
    except Exception as e:
        return False, str(e)


def get_timestamp():
    """Get formatted timestamp for filenames"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def get_display_timestamp():
    """Get formatted timestamp for display"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def save_summary_report(filename, summary_data):
    """
    Save summary report to text file
    
    Args:
        filename: Name of the summary file
        summary_data: Dictionary containing summary information
    """
    filepath = os.path.join(LOG_DIRECTORY, filename)
    
    try:
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 20 + "SECURITY MONITORING SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            for section, content in summary_data.items():
                f.write(f"\n{section}\n")
                f.write("-" * 80 + "\n")
                
                if isinstance(content, dict):
                    for key, value in content.items():
                        f.write(f"  {key}: {value}\n")
                elif isinstance(content, list):
                    for item in content:
                        f.write(f"  - {item}\n")
                else:
                    f.write(f"  {content}\n")
        
        return True, filepath
    except Exception as e:
        return False, str(e)


# ============================================
# DISPLAY UTILITIES
# ============================================
def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 90)
    print(" " * ((90 - len(title)) // 2) + title)
    print("=" * 90)


def print_section(title):
    """Print formatted section header"""
    print("\n" + "─" * 90)
    print(title)
    print("─" * 90)


def clear_screen():
    """Clear terminal screen"""
    print("\n" * 5)  # Simple clear method