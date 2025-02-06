from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
import os
import logging
from logging.handlers import RotatingFileHandler
from packet_analyzer import analyze_pcap

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['LOG_FOLDER'] = 'logs'

# Ensure required directories exist
required_dirs = [
    app.config['UPLOAD_FOLDER'],
    app.config['LOG_FOLDER'],
]

for directory in required_dirs:
    os.makedirs(directory, exist_ok=True)
    # Ensure directory has proper permissions (rwx for user, rx for group)
    os.chmod(directory, 0o755)

# Configure logging
log_file = os.path.join(app.config['LOG_FOLDER'], 'packet_analyzer.log')
handler = RotatingFileHandler(log_file, maxBytes=10000000, backupCount=5)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Error rendering index page: {str(e)}")
        return "An error occurred", 500

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            app.logger.warning("No file part in request")
            return 'No file part', 400
        
        file = request.files['file']
        if file.filename == '':
            app.logger.warning("No selected file")
            return 'No selected file', 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Log upload attempt
            app.logger.info(f"Processing upload: {filename}")
            
            try:
                file.save(filepath)
                
                # Analyze the pcap file
                analysis_results = analyze_pcap(filepath)
                
                # Clean up the uploaded file
                os.remove(filepath)
                
                app.logger.info(f"Successfully analyzed file: {filename}")
                return render_template('results.html', results=analysis_results)
                
            except Exception as e:
                app.logger.error(f"Error processing file {filename}: {str(e)}")
                if os.path.exists(filepath):
                    os.remove(filepath)
                return f"Error processing file: {str(e)}", 500
        
        app.logger.warning(f"Invalid file type attempted: {file.filename}")
        return 'Invalid file type', 400
        
    except Exception as e:
        app.logger.error(f"Unexpected error in upload: {str(e)}")
        return "An unexpected error occurred", 500

@app.errorhandler(413)
def too_large(e):
    app.logger.warning("File too large attempted to upload")
    return "File is too large (max 16MB)", 413

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Internal server error: {str(e)}")
    return "Internal server error", 500

if __name__ == '__main__':
    app.logger.info("Starting application...")
    app.run(debug=True)
