import random
import string
import json
import hashlib
import base64
import gzip
import io
import re

def process_unique_files(vulnerabilities_data):
    """
    Process vulnerability files to extract unique file contents.
    Returns a dictionary of unique file hashes with their gzipped+base64 encoded content.
    
    Args:
        vulnerabilities_data: List of vulnerability data items containing file paths
    
    Returns:
        dict: Dictionary mapping file hashes to compressed+encoded content
    """
    unique_files = {}
    
    # Skip the header row
    iterdata = iter(vulnerabilities_data)
    next(iterdata)
    
    for item in iterdata:
        file_path = item[2].split(":")[0]
        try:
            # Read the file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
            
            # Calculate SHA256 hash
            content_hash = hashlib.sha256(file_content).hexdigest()
            
            # Only process this file if we haven't seen this hash before
            if content_hash not in unique_files:
                # Compress with gzip
                gzip_content = io.BytesIO()
                with gzip.GzipFile(fileobj=gzip_content, mode='wb') as f:
                    f.write(file_content)

                # Base64 encode the compressed content
                compressed_b64 = base64.b64encode(gzip_content.getvalue()).decode('utf-8')
                
                # Store in our unique files dictionary
                unique_files[content_hash] = compressed_b64
        except Exception as e:
            # Log the error but continue processing
            print(f"Error processing file {file_path}: {str(e)}")
    
    return unique_files

def save_report(name, data, path):
    filename = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    output = []
    
    # Process unique files for vulnerabilities
    if name == 'vulnerabilities':
        unique_files = process_unique_files(data)
        
        # Create separate JSON file for unique file contents
        with open('reports/' + path.split("/")[-1] + filename + '_file_contents.json', 'w') as outfile:
            json.dump(unique_files, outfile)
        
        # Continue with regular vulnerability processing
        iterdata = iter(data)
        next(iterdata)
        for item in iterdata:
            # Calculate the hash to reference in the file_contents
            try:
                with open(item[2].split(":")[0], 'rb') as f:
                    file_content = f.read()
                content_hash = hashlib.sha256(file_content).hexdigest()

                output.append({
                    'function': __(item[0]),
                    'file': __(item[1]),
                    'user_input': __(item[2]),
                    'content_hash': content_hash  # Reference to the content in file_contents.json
                })
            except Exception as e:
                output.append({
                    'function': __(item[0]),
                    'file': __(item[1]),
                    'user_input': __(item[2]),
                    'error': str(e)
                })
    # Handle other report types as before
    elif name == 'admin_actions':
        iterdata = iter(data)
        next(iterdata)
        for item in iterdata:
            output.append({
                'action_name': __(item[0]),
                'function': __(item[1]),
                'file': __(item[2])
            })
    elif name == 'ajax_hooks':
        iterdata = iter(data)
        next(iterdata)
        for item in iterdata:
            output.append({
                'action_name': __(item[0]),
                'function': __(item[1]),
                'file': __(item[2]),
                'user_input': __(item[3])
            })
    elif name == 'admin_init':
        iterdata = iter(data)
        next(iterdata)
        for item in iterdata:
            output.append({
                'function': __(item[0]),
                'file': __(item[1]),
                'user_input': __(item[2])
            })
    
    # Save the main output file
    with open('reports/' + path.split("/")[-1] + filename + '_' + name + '.json', 'w') as outfile:
        json.dump(output, outfile)

def __(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)