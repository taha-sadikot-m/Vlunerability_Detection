# app.py - Main Flask Application
from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime
import asyncio
import threading
from vulnerability_scanner import VulnerabilityScanner
from langgraph_workflow import VulnerabilityDetectionWorkflow
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Enable CORS and SocketIO
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize components
scanner = VulnerabilityScanner()
workflow = VulnerabilityDetectionWorkflow()

# Store active scans
active_scans = {}

@app.route('/')
def index():
    """Serve the main HTML page"""
    return render_template('index.html')

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "VulnDetect AI Backend",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        # Get scan configuration from request
        config = request.get_json()
        
        # Validate required fields
        if not config or 'files' not in config:
            return jsonify({"error": "No files provided"}), 400
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Store scan configuration
        active_scans[scan_id] = {
            "id": scan_id,
            "status": "initiated",
            "config": config,
            "results": {},
            "progress": 0,
            "start_time": datetime.utcnow().isoformat()
        }
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=run_vulnerability_scan,
            args=(scan_id, config)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            "scan_id": scan_id,
            "status": "initiated",
            "message": "Vulnerability scan started successfully"
        }), 202
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({"error": "Failed to start scan"}), 500

@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get the status of a specific scan"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan_data = active_scans[scan_id]
    return jsonify({
        "scan_id": scan_id,
        "status": scan_data["status"],
        "progress": scan_data["progress"],
        "start_time": scan_data["start_time"],
        "results": scan_data.get("results", {})
    })

@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get the complete results of a scan"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan_data = active_scans[scan_id]
    
    if scan_data["status"] != "completed":
        return jsonify({
            "error": "Scan not completed yet",
            "status": scan_data["status"],
            "progress": scan_data["progress"]
        }), 202
    
    return jsonify(scan_data["results"])

@app.route('/api/scan/<scan_id>/report', methods=['GET'])
def export_scan_report(scan_id):
    """Export scan results in different formats"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scan_data = active_scans[scan_id]
    format_type = request.args.get('format', 'json').lower()
    
    if scan_data["status"] != "completed":
        return jsonify({"error": "Scan not completed"}), 202
    
    results = scan_data["results"]
    
    if format_type == 'csv':
        # Convert to CSV format
        csv_content = scanner.export_to_csv(results)
        return csv_content, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=vulnerability_report_{scan_id}.csv'
        }
    elif format_type == 'pdf':
        # Convert to PDF format (would need additional implementation)
        return jsonify({"error": "PDF export not implemented yet"}), 501
    else:
        # Default JSON format
        return jsonify(results)

def run_vulnerability_scan(scan_id, config):
    """Run the complete vulnerability scanning workflow"""
    try:
        # Update scan status
        active_scans[scan_id]["status"] = "running"
        emit_progress_update(scan_id, 5, "Initializing scan...")
        
        # Initialize the LangGraph workflow
        workflow_state = {
            "scan_id": scan_id,
            "config": config,
            "files": config.get("files", []),
            "scan_options": {
                "sast_enabled": config.get("sast_enabled", True),
                "dependency_scan": config.get("dependency_scan", True),
                "llm_analysis": config.get("llm_analysis", True),
                "cve_lookup": config.get("cve_lookup", True),
                "deep_analysis": config.get("deep_analysis", False)
            },
            "results": {
                "vulnerabilities": [],
                "dependencies": [],
                "cves": [],
                "cwes": [],
                "summary": {},
                "recommendations": []
            },
            "progress": 5
        }
        
        # Run the LangGraph workflow
        final_state = workflow.run(workflow_state, progress_callback=lambda p, m: emit_progress_update(scan_id, p, m))
        
        # Store final results
        active_scans[scan_id]["results"] = final_state["results"]
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["end_time"] = datetime.utcnow().isoformat()
        
        # Emit completion event
        emit_progress_update(scan_id, 100, "Scan completed successfully!")
        
        # Emit final results
        socketio.emit('scan_completed', {
            "scan_id": scan_id,
            "results": final_state["results"]
        })
        
    except Exception as e:
        logger.error(f"Error in vulnerability scan {scan_id}: {str(e)}")
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        
        socketio.emit('scan_error', {
            "scan_id": scan_id,
            "error": str(e)
        })

def emit_progress_update(scan_id, progress, message):
    """Emit progress update via WebSocket"""
    active_scans[scan_id]["progress"] = progress
    
    socketio.emit('scan_progress', {
        "scan_id": scan_id,
        "progress": progress,
        "message": message,
        "timestamp": datetime.utcnow().isoformat()
    })

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to VulnDetect AI Backend'})
    logger.info("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("Client disconnected")

@socketio.on('subscribe_scan')
def handle_scan_subscription(data):
    """Handle scan subscription for real-time updates"""
    scan_id = data.get('scan_id')
    if scan_id and scan_id in active_scans:
        emit('subscribed', {'scan_id': scan_id})
        logger.info(f"Client subscribed to scan {scan_id}")

if __name__ == '__main__':
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Validate required environment variables
    required_vars = ['GEMINI_API_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        exit(1)
    
    # Start the Flask-SocketIO server
    logger.info("Starting VulnDetect AI Backend...")
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development',
        allow_unsafe_werkzeug=True
    )