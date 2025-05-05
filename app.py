from flask import Flask, render_template, request, flash, redirect, url_for # type: ignore
import os
from werkzeug.utils import secure_filename
import joblib
import magic
import tempfile
import numpy as np
import traceback
import pickle
import pefile  # For parsing PE files
import hashlib
from dotenv import load_dotenv
from virus_total_apis import PublicApi as VirusTotalPublicApi
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Load environment variables
load_dotenv()

# Initialize VirusTotal API with rate limiting
vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
if vt_api_key:
    vt_api = VirusTotalPublicApi(vt_api_key)
    # Rate limiting: 4 requests per minute (free tier)
    vt_last_request = 0
    vt_request_interval = 15  # seconds (60/4 = 15)
else:
    print("Warning: VirusTotal API key not found. Some features will be disabled.")
    vt_api = None

# Load the trained model
model = None
model_error = None

try:
    print("Attempting to load model...")
    with open('ransomware_detector_20250417_074204.joblib', 'rb') as f:
        model = pickle.load(f)
    print(f"Model loaded successfully. Type: {type(model)}")
    print(f"Model shape: {model.shape if hasattr(model, 'shape') else 'No shape'}")
    print(f"Model dtype: {model.dtype if hasattr(model, 'dtype') else 'No dtype'}")
    print(f"Model content sample: {model[:5] if hasattr(model, '__getitem__') else model}")
except Exception as e:
    model_error = str(e)
    print(f"Error loading model: {model_error}")
    print("Traceback:")
    print(traceback.format_exc())

ALLOWED_EXTENSIONS = {'exe', 'dll', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'zip', 'rar'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_virustotal_report(file_hash):
    """Get VirusTotal report for a file hash with rate limiting"""
    if not vt_api:
        return None
    
    global vt_last_request
    
    # Implement rate limiting
    current_time = time.time()
    time_since_last_request = current_time - vt_last_request
    
    if time_since_last_request < vt_request_interval:
        time.sleep(vt_request_interval - time_since_last_request)
    
    try:
        response = vt_api.get_file_report(file_hash)
        vt_last_request = time.time()
        
        if response['response_code'] == 200:
            return response['results']
        return None
    except Exception as e:
        print(f"Error getting VirusTotal report: {str(e)}")
        return None

def extract_pe_features(file_path):
    """Extract PE header features from the file"""
    try:
        pe = pefile.PE(file_path)
        features = {}
        
        # Extract basic PE header information
        features['Machine'] = pe.FILE_HEADER.Machine
        features['DebugSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        features['DebugRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        features['MajorOSVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        
        # Extract section information
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        
        # Extract import/export information
        features['NumberOfImports'] = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
        features['NumberOfExports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        
        # Extract resource information
        features['NumberOfResources'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
        
        # Check for suspicious characteristics
        features['IsDLL'] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        features['IsExecutable'] = bool(pe.FILE_HEADER.Characteristics & 0x2)
        features['IsLargeAddressAware'] = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x20)
        
        pe.close()
        return features
    except Exception as e:
        if 'pe' in locals():
            pe.close()
        raise Exception(f"Error extracting PE features: {str(e)}")

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read the file in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_file(file_path):
    try:
        if model is None:
            if model_error:
                raise Exception(f"Model not loaded properly: {model_error}")
            else:
                raise Exception("Model not loaded properly")
        
        # Calculate file hash
        file_hash = calculate_file_hash(file_path)
        
        # Get VirusTotal report
        vt_report = get_virustotal_report(file_hash)
        
        # Known ransomware hashes
        known_ransomware_hashes = {
            'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa': 'WannaCry Ransomware',
            '0b5b31af5956158bfbd14f6cbf4f1bca23c5d16a40dbf3758f3289146c565f43': 'akira Ransomware',
            'a2df5477cf924bd41241a3326060cc2f913aff2379858b148ddec455e4da67bc': 'akira Ransomware',
            

            

            # Add more known ransomware hashes here
        }
        
        # Check against known ransomware hashes
        if file_hash in known_ransomware_hashes:
            return {
                'is_safe': False,
                'is_ransomware': True,
                'is_malware': False,
                'confidence': 100.0,
                'file_type': magic.from_file(file_path),
                'suspicious_fields': [],
                'suspicious_reasons': [],
                'ransomware_indicators': [f"Known ransomware hash match: {known_ransomware_hashes[file_hash]}"],
                'malware_indicators': [],
                'file_hash': file_hash,
                'virustotal_report': vt_report
            }
        
        # Extract PE features
        features = extract_pe_features(file_path)
        
        # Initialize detection arrays
        suspicious_fields = []
        suspicious_reasons = []
        ransomware_indicators = []
        malware_indicators = []
        
        # Check for ransomware-specific characteristics
        try:
            pe = pefile.PE(file_path)
            
            # Check for encryption-related imports
            crypto_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    if any(crypto in dll_name for crypto in ['crypt', 'encrypt', 'crypto']):
                        crypto_imports.append(dll_name)
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode().lower()
                                if any(crypto in imp_name for crypto in ['encrypt', 'decrypt', 'crypt', 'aes', 'rc4', 'rsa', 'xor']):
                                    ransomware_indicators.append(f"Cryptographic function: {imp_name} from {dll_name}")
            
            # Check for file system operations
            file_ops = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    if 'kernel32' in dll_name or 'advapi32' in dll_name:
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode().lower()
                                if any(op in imp_name for op in ['findfirst', 'findnext', 'createfile', 'writefile', 'deletefile', 'movefile', 'copyfile']):
                                    file_ops.append(f"File operation: {imp_name} from {dll_name}")
            
            # Check for network operations
            network_ops = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    if 'ws2_32' in dll_name or 'wininet' in dll_name:
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode().lower()
                                if any(net in imp_name for net in ['connect', 'send', 'recv', 'socket', 'http', 'url']):
                                    network_ops.append(f"Network operation: {imp_name} from {dll_name}")
            
            # Check for specific ransomware behaviors
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode().lower()
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode().lower()
                            # Check for ransom note creation
                            if any(note in imp_name for note in ['createfile', 'writefile']):
                                ransomware_indicators.append(f"Potential ransom note creation: {imp_name} from {dll_name}")
                            # Check for file extension modification
                            if any(ext in imp_name for ext in ['movefile', 'copyfile']):
                                ransomware_indicators.append(f"Potential file extension modification: {imp_name} from {dll_name}")
            
            pe.close()
            
            # Enhanced ransomware detection logic
            is_ransomware = (
                len(crypto_imports) > 0 and  # Has encryption functions
                len(file_ops) > 0 and        # Has file operations
                (
                    len(network_ops) > 0 or  # Has network capabilities
                    len(ransomware_indicators) >= 2  # Or has multiple ransomware indicators
                )
            )
            
            if is_ransomware:
                ransomware_indicators.extend(file_ops)
                ransomware_indicators.extend(network_ops)
        
        except Exception as e:
            print(f"Error analyzing PE file: {str(e)}")
        
        for field in model:
            if field in features:
                value = features[field]
                
                # Add specific checks for each field
                if field == 'Machine':
                    if value not in [0x014c, 0x8664]:  # x86 and x64
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusual machine type: {hex(value)}")
                
                elif field == 'DebugSize':
                    if value == 0:
                        suspicious_fields.append(field)
                        suspicious_reasons.append("No debug information (common in malware)")
                
                elif field == 'DebugRVA':
                    if value == 0:
                        suspicious_fields.append(field)
                        suspicious_reasons.append("No debug information (common in malware)")
                
                elif field == 'MajorImageVersion':
                    if value == 0:
                        suspicious_fields.append(field)
                        suspicious_reasons.append("No version information (common in malware)")
                
                elif field == 'MajorOSVersion':
                    if value < 5:  # Windows 2000 or older
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusually old OS version: {value}")
                
                elif field == 'NumberOfSections':
                    if value < 3 or value > 20:  # Unusual number of sections
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusual number of sections: {value}")
                
                elif field == 'SizeOfCode':
                    if value < 1024 or value > 50*1024*1024:  # Too small or too large
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusual code size: {value} bytes")
                
                elif field == 'NumberOfImports':
                    if value < 5:  # Very few imports
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Very few imports: {value}")
                    elif value > 200:  # Too many imports
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusually high number of imports: {value}")
                
                elif field == 'NumberOfExports':
                    if value > 0 and not features.get('IsDLL', False):
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Non-DLL with exports: {value}")
                
                elif field == 'NumberOfResources':
                    if value > 50:  # Unusually high number of resources
                        suspicious_fields.append(field)
                        suspicious_reasons.append(f"Unusually high number of resources: {value}")
                
                elif field == 'IsDLL':
                    if value and not file_path.lower().endswith('.dll'):
                        suspicious_fields.append(field)
                        suspicious_reasons.append("DLL characteristics in non-DLL file")
                
                elif field == 'IsExecutable':
                    if not value:
                        suspicious_fields.append(field)
                        suspicious_reasons.append("Not marked as executable")
                
                elif field == 'IsLargeAddressAware':
                    if not value:
                        suspicious_fields.append(field)
                        suspicious_reasons.append("Not large address aware (unusual for modern executables)")
        
        # Calculate confidence and safety
        confidence = 100.0 - (len(suspicious_fields) / len(model) * 100)
        
        # Enhance confidence based on VirusTotal report
        if vt_report:
            # Calculate detection ratio
            total_engines = vt_report.get('total', 0)
            positive_detections = vt_report.get('positives', 0)
            if total_engines > 0:
                detection_ratio = (positive_detections / total_engines) * 100
                # Adjust confidence based on VirusTotal detection ratio
                confidence = max(confidence, detection_ratio)
            
            # Add VirusTotal detection names to indicators
            if 'scans' in vt_report:
                for engine, result in vt_report['scans'].items():
                    if result['detected']:
                        if 'ransomware' in result['result'].lower():
                            ransomware_indicators.append(f"VirusTotal {engine}: {result['result']}")
                        else:
                            malware_indicators.append(f"VirusTotal {engine}: {result['result']}")
        
        # Determine threat type
        is_malware = len(malware_indicators) >= 2 or (len(suspicious_fields) >= 2 and not is_ransomware)
        is_safe = len(suspicious_fields) < 2 and not is_ransomware and not is_malware
        
        return {
            'is_safe': is_safe,
            'is_ransomware': is_ransomware,
            'is_malware': is_malware,
            'confidence': max(0.0, min(100.0, confidence)),
            'file_type': magic.from_file(file_path),
            'suspicious_fields': suspicious_fields,
            'suspicious_reasons': suspicious_reasons,
            'ransomware_indicators': ransomware_indicators,
            'malware_indicators': malware_indicators,
            'file_hash': file_hash,
            'virustotal_report': vt_report
        }
    except Exception as e:
        print(f"Error in analyze_file: {str(e)}")
        print("Traceback:")
        print(traceback.format_exc())
        return {
            'error': str(e)
        }

@app.route('/')
def index():
    if model is None:
        if model_error:
            flash(f'Warning: Model not loaded properly: {model_error}')
        else:
            flash('Warning: Model not loaded properly. Please check the server logs.')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            result = analyze_file(file_path)
            if 'error' in result:
                flash(f'Error analyzing file: {result["error"]}')
            else:
                if result['is_ransomware']:
                    status = "RANSOMWARE"
                elif result['is_malware']:
                    status = "MALWARE"
                else:
                    status = "SAFE" if result['is_safe'] else "DANGEROUS"
                
                message = f'File Analysis Results:\nStatus: {status}\nConfidence: {result["confidence"]:.2f}%\nFile Type: {result["file_type"]}\nSHA-256 Hash: {result["file_hash"]}'
                
                # Add VirusTotal information if available
                if result.get('virustotal_report'):
                    vt_report = result['virustotal_report']
                    if 'positives' in vt_report and 'total' in vt_report:
                        message += f'\n\nVirusTotal Detection: {vt_report["positives"]}/{vt_report["total"]} engines detected this file'
                        if 'permalink' in vt_report:
                            message += f'\nVirusTotal Report: {vt_report["permalink"]}'
                
                if result['is_ransomware'] and result['ransomware_indicators']:
                    message += f'\n\nRansomware Indicators:'
                    for indicator in result['ransomware_indicators']:
                        message += f'\n- {indicator}'
                
                if result['is_malware'] and result['malware_indicators']:
                    message += f'\n\nMalware Indicators:'
                    for indicator in result['malware_indicators']:
                        message += f'\n- {indicator}'
                
                if 'suspicious_fields' in result and result['suspicious_fields']:
                    message += f'\n\nSuspicious Indicators:'
                    for field, reason in zip(result['suspicious_fields'], result['suspicious_reasons']):
                        message += f'\n- {field}: {reason}'
                
                flash(message)
        finally:
            # Clean up the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)
        
        return redirect(url_for('index'))
    
    flash('File type not allowed')
    return redirect(request.url)

if __name__ == '__main__':
    app.run(debug=True) 