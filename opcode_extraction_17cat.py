import os
import sys
import argparse
import pandas as pd
from tqdm import tqdm
import subprocess
import tempfile
import shutil
import re
import zipfile
import time
import logging
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("apk_processing.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("apk_processor")

# Define the symbolic mapping based on the 17-category classification
OPCODE_SYMBOLS = {
    # Category 1: nop (N)
    'nop': 'N',
    
    # Category 2: move (M)
    'move': 'M', 'move/from16': 'M', 'move/16': 'M', 'move-wide': 'M', 'move-wide/from16': 'M',
    'move-wide/16': 'M', 'move-object': 'M', 'move-object/from16': 'M', 'move-object/16': 'M',
    'move-result': 'M', 'move-result-wide': 'M', 'move-result-object': 'M', 'move-exception': 'M',
    
    # Category 3: return (R)
    'return-void': 'R', 'return': 'R', 'return-wide': 'R', 'return-object': 'R',
    
    # Category 4: monitor (L)
    'monitor-enter': 'L', 'monitor-exit': 'L',
    
    # Category 5: test (T)
    'cmpl-float': 'T', 'cmpg-float': 'T', 'cmpl-double': 'T', 'cmpg-double': 'T', 'cmp-long': 'T',
    'check-cast': 'T', 'instance-of': 'T',
    
    # Category 6: new (W)
    'new-instance': 'W', 'new-array': 'W', 'filled-new-array': 'W', 'filled-new-array/range': 'W',
    
    # Category 7: throw (H)
    'throw': 'H',
    
    # Category 8: jump (J)
    'goto': 'J', 'goto/16': 'J', 'goto/32': 'J',
    
    # Category 9: branch (B)
    'if-eq': 'B', 'if-ne': 'B', 'if-lt': 'B', 'if-ge': 'B', 'if-gt': 'B', 'if-le': 'B',
    'if-eqz': 'B', 'if-nez': 'B', 'if-ltz': 'B', 'if-gez': 'B', 'if-gtz': 'B', 'if-lez': 'B',
    'packed-switch': 'B', 'sparse-switch': 'B',
    
    # Category 10: arrayop (A)
    'aget': 'A', 'aget-wide': 'A', 'aget-object': 'A', 'aget-boolean': 'A', 'aget-byte': 'A',
    'aget-char': 'A', 'aget-short': 'A', 'aput': 'A', 'aput-wide': 'A', 'aput-object': 'A',
    'aput-boolean': 'A', 'aput-byte': 'A', 'aput-char': 'A', 'aput-short': 'A', 'array-length': 'A',
    'fill-array-data': 'A',
    
    # Category 11: instanceop (I)
    'iget': 'I', 'iget-wide': 'I', 'iget-object': 'I', 'iget-boolean': 'I', 'iget-byte': 'I',
    'iget-char': 'I', 'iget-short': 'I', 'iput': 'I', 'iput-wide': 'I', 'iput-object': 'I',
    'iput-boolean': 'I', 'iput-byte': 'I', 'iput-char': 'I', 'iput-short': 'I',
    
    # Category 12: staticop (S)
    'sget': 'S', 'sget-wide': 'S', 'sget-object': 'S', 'sget-boolean': 'S', 'sget-byte': 'S',
    'sget-char': 'S', 'sget-short': 'S', 'sput': 'S', 'sput-wide': 'S', 'sput-object': 'S',
    'sput-boolean': 'S', 'sput-byte': 'S', 'sput-char': 'S', 'sput-short': 'S',
    
    # Category 13: invoke (V)
    'invoke-virtual': 'V', 'invoke-super': 'V', 'invoke-direct': 'V', 'invoke-static': 'V',
    'invoke-interface': 'V', 'invoke-virtual/range': 'V', 'invoke-super/range': 'V',
    'invoke-direct/range': 'V', 'invoke-static/range': 'V', 'invoke-interface/range': 'V',
    'invoke-virtual-quick': 'V', 'invoke-virtual-quick/range': 'V',
    
    # Category 14: unop (U)
    'neg-int': 'U', 'not-int': 'U', 'neg-long': 'U', 'not-long': 'U', 'neg-float': 'U',
    'neg-double': 'U', 'int-to-long': 'U', 'int-to-float': 'U', 'int-to-double': 'U',
    'long-to-int': 'U', 'long-to-float': 'U', 'long-to-double': 'U', 'float-to-int': 'U',
    'float-to-long': 'U', 'float-to-double': 'U', 'double-to-int': 'U', 'double-to-long': 'U',
    'double-to-float': 'U', 'int-to-byte': 'U', 'int-to-char': 'U', 'int-to-short': 'U',
    
    # Category 15: binop (O)
    'add-int': 'O', 'sub-int': 'O', 'mul-int': 'O', 'div-int': 'O', 'rem-int': 'O',
    'and-int': 'O', 'or-int': 'O', 'xor-int': 'O', 'shl-int': 'O', 'shr-int': 'O',
    'ushr-int': 'O', 'add-long': 'O', 'sub-long': 'O', 'mul-long': 'O', 'div-long': 'O',
    'rem-long': 'O', 'and-long': 'O', 'or-long': 'O', 'xor-long': 'O', 'shl-long': 'O',
    'shr-long': 'O', 'ushr-long': 'O', 'add-float': 'O', 'sub-float': 'O', 'mul-float': 'O',
    'div-float': 'O', 'rem-float': 'O', 'add-double': 'O', 'sub-double': 'O', 'mul-double': 'O',
    'div-double': 'O', 'rem-double': 'O', 'add-int/2addr': 'O', 'sub-int/2addr': 'O',
    'mul-int/2addr': 'O', 'div-int/2addr': 'O', 'rem-int/2addr': 'O', 'and-int/2addr': 'O',
    'or-int/2addr': 'O', 'xor-int/2addr': 'O', 'shl-int/2addr': 'O', 'shr-int/2addr': 'O',
    'ushr-int/2addr': 'O', 'add-long/2addr': 'O', 'sub-long/2addr': 'O', 'mul-long/2addr': 'O',
    'div-long/2addr': 'O', 'rem-long/2addr': 'O', 'and-long/2addr': 'O', 'or-long/2addr': 'O',
    'xor-long/2addr': 'O', 'shl-long/2addr': 'O', 'shr-long/2addr': 'O', 'ushr-long/2addr': 'O',
    'add-float/2addr': 'O', 'sub-float/2addr': 'O', 'mul-float/2addr': 'O', 'div-float/2addr': 'O',
    'rem-float/2addr': 'O', 'add-double/2addr': 'O', 'sub-double/2addr': 'O', 'mul-double/2addr': 'O',
    'div-double/2addr': 'O', 'rem-double/2addr': 'O', 'add-int/lit16': 'O', 'rsub-int': 'O',
    'mul-int/lit16': 'O', 'div-int/lit16': 'O', 'rem-int/lit16': 'O', 'and-int/lit16': 'O',
    'or-int/lit16': 'O', 'xor-int/lit16': 'O', 'add-int/lit8': 'O', 'rsub-int/lit8': 'O',
    'mul-int/lit8': 'O', 'div-int/lit8': 'O', 'rem-int/lit8': 'O', 'and-int/lit8': 'O',
    'or-int/lit8': 'O', 'xor-int/lit8': 'O', 'shl-int/lit8': 'O', 'shr-int/lit8': 'O',
    'ushr-int/lit8': 'O', 'const/4': 'O', 'const/16': 'O', 'const': 'O', 'const/high16': 'O',
    'const-wide/16': 'O', 'const-wide/32': 'O', 'const-wide': 'O', 'const-wide/high16': 'O',
    'const-string': 'O', 'const-string/jumbo': 'O', 'const-class': 'O',
    
    # Category 16: invoke-polymorphic (P)
    'invoke-polymorphic': 'P', 'invoke-polymorphic/range': 'P', 'invoke-custom': 'P', 'invoke-custom/range': 'P',
    
    # Category 17: const-method (F)
    'const-method-handle': 'F', 'const-method-type': 'F'
}

# No synthetic symbol generation - we only use actual extracted opcodes

def verify_apk(apk_path):
    """
    Verify that the APK file is valid
    
    Args:
        apk_path: Path to the APK file
    
    Returns:
        True if valid, False otherwise
    """
    try:
        # Check if it's a valid zip file
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            # Check for presence of classes.dex
            dex_files = [f for f in zip_ref.namelist() if f.endswith('.dex')]
            if not dex_files:
                logger.warning(f"No DEX files found in {apk_path}")
                return False
            
            # Try to extract META-INF/MANIFEST.MF
            manifests = [f for f in zip_ref.namelist() if f.endswith('MANIFEST.MF')]
            if not manifests:
                logger.warning(f"No MANIFEST.MF found in {apk_path}")
                # Not a critical error, continue
            
            # Apk is probably valid
            return True
    except zipfile.BadZipFile:
        logger.error(f"Invalid zip file: {apk_path}")
        return False
    except Exception as e:
        logger.error(f"Error verifying APK {apk_path}: {str(e)}")
        return False

def extract_dex_files(apk_path, output_dir):
    """
    Extract DEX files directly from APK without using apktool
    
    Args:
        apk_path: Path to the APK file
        output_dir: Directory to extract DEX files to
    
    Returns:
        List of extracted DEX file paths, or empty list if failed
    """
    dex_files = []
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            for item in zip_ref.namelist():
                if item.endswith('.dex'):
                    output_path = os.path.join(output_dir, os.path.basename(item))
                    with zip_ref.open(item) as source, open(output_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
                    dex_files.append(output_path)
        
        logger.info(f"Extracted {len(dex_files)} DEX files from {apk_path}")
        return dex_files
    except Exception as e:
        logger.error(f"Error extracting DEX files from {apk_path}: {str(e)}")
        return []

def extract_dex_to_temp(apk_path, max_retries=3, use_memory_opts=True):
    """
    Extract APK to temporary directory using apktool with fallback options
    
    Args:
        apk_path: Path to the APK file
        max_retries: Maximum number of retry attempts
        use_memory_opts: Use Java memory options for large APKs
    
    Returns:
        Path to temporary directory with smali files, or None if failed
    """
    temp_dir = tempfile.mkdtemp(prefix="smali_")
    
    # Try apktool first (standard method)
    logger.info(f"Attempting to extract {apk_path} with apktool")
    
    for attempt in range(max_retries):
        try:
            # Set Java memory options if needed
            java_opts = ""
            if use_memory_opts:
                java_opts = "JAVA_OPTS='-Xmx4g -XX:+UseG1GC'"
            
            # Try with different apktool options on each attempt
            if attempt == 0:
                # First attempt: standard options
                cmd = f'{java_opts} apktool d {apk_path} -o {temp_dir} -f'
            elif attempt == 1:
                # Second attempt: add --no-src option (don't decode source)
                cmd = f'{java_opts} apktool d {apk_path} -o {temp_dir} -f --no-src'
            else:
                # Third attempt: add --no-res option (don't decode resources)
                cmd = f'{java_opts} apktool d {apk_path} -o {temp_dir} -f --no-src --no-res'
            
            logger.info(f"Attempt {attempt+1}: {cmd}")
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            
            if result.returncode == 0:
                # Check if smali directory exists
                smali_dir = os.path.join(temp_dir, "smali")
                if not os.path.exists(smali_dir):
                    logger.warning(f"No smali directory found in {temp_dir}")
                    # Check for other possible smali directories
                    smali_dirs = []
                    for dir_name in os.listdir(temp_dir):
                        if dir_name.startswith("smali"):
                            smali_dirs.append(os.path.join(temp_dir, dir_name))
                    
                    if smali_dirs:
                        logger.info(f"Found alternative smali directories: {smali_dirs}")
                        return temp_dir
                    else:
                        logger.error(f"No smali directories found in {temp_dir}")
                        # Continue to next attempt
                else:
                    logger.info(f"Successfully extracted {apk_path} with apktool")
                    return temp_dir
            else:
                logger.warning(f"apktool failed on attempt {attempt+1}: {result.stderr.decode('utf-8')}")
                # Clean up for next attempt
                shutil.rmtree(temp_dir, ignore_errors=True)
                temp_dir = tempfile.mkdtemp(prefix="smali_")
                
                # Add a small delay between attempts
                time.sleep(1)
        
        except subprocess.TimeoutExpired:
            logger.warning(f"apktool timed out on attempt {attempt+1}")
            # Clean up for next attempt
            shutil.rmtree(temp_dir, ignore_errors=True)
            temp_dir = tempfile.mkdtemp(prefix="smali_")
        
        except Exception as e:
            logger.warning(f"Exception during extraction attempt {attempt+1}: {str(e)}")
            # Clean up for next attempt
            shutil.rmtree(temp_dir, ignore_errors=True)
            temp_dir = tempfile.mkdtemp(prefix="smali_")
    
    # If apktool failed, try direct DEX extraction and baksmali
    logger.info(f"apktool failed after {max_retries} attempts, trying direct DEX extraction")
    
    try:
        # Extract DEX files directly
        dex_dir = tempfile.mkdtemp(prefix="dex_")
        dex_files = extract_dex_files(apk_path, dex_dir)
        
        if not dex_files:
            logger.error(f"No DEX files extracted from {apk_path}")
            shutil.rmtree(dex_dir, ignore_errors=True)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
        
        # Process each DEX file with baksmali
        success = False
        for i, dex_file in enumerate(dex_files):
            # Create smali_classes<i+1> directory
            smali_subdir = f"smali{'_classes' + str(i+1) if i > 0 else ''}"
            smali_dir = os.path.join(temp_dir, smali_subdir)
            os.makedirs(smali_dir, exist_ok=True)
            
            # Use baksmali to decompile the DEX file
            cmd = f'baksmali d {dex_file} -o {smali_dir}'
            try:
                result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
                if result.returncode == 0:
                    logger.info(f"Successfully processed {dex_file} with baksmali")
                    success = True
                else:
                    logger.warning(f"baksmali failed for {dex_file}: {result.stderr.decode('utf-8')}")
            except Exception as e:
                logger.warning(f"Exception running baksmali on {dex_file}: {str(e)}")
        
        # Clean up DEX directory
        shutil.rmtree(dex_dir, ignore_errors=True)
        
        if success:
            logger.info(f"Successfully extracted {apk_path} using direct DEX extraction and baksmali")
            return temp_dir
        else:
            logger.error(f"All extraction methods failed for {apk_path}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return None
        
    except Exception as e:
        logger.error(f"Exception extracting {apk_path} with direct method: {str(e)}")
        shutil.rmtree(dex_dir, ignore_errors=True)
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None

def extract_opcodes_from_smali(smali_file_path):
    """
    Extract opcodes from a smali file
    
    Args:
        smali_file_path: Path to the smali file
    
    Returns:
        List of opcodes
    """
    opcodes = []
    
    try:
        with open(smali_file_path, mode="r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Extract opcodes using regex pattern for smali format
        # Pattern matches: instruction opcode (e.g., "invoke-virtual", "const-string", etc.)
        opcode_pattern = r'^\s*([a-z-]+)(?:/|\s|$)'
        matches = re.findall(opcode_pattern, content, re.MULTILINE)
        
        for opcode in matches:
            # Skip non-opcode lines (labels, comments, etc.)
            if opcode in ['nop', 'label', 'line', 'parameter', 'local', 'restart', 'annotation', 'end', 'catch', 
                          'catchall', 'prologue', 'epilogue', 'registers', 'locals', 'array-data', 'method',
                          'end', 'sparse-switch-data', 'packed-switch-data', 'field', 'subannotation']:
                continue
            # Extract the base opcode (before any /)
            base_opcode = opcode.split('/')[0]
            opcodes.append(base_opcode)
            
    except UnicodeDecodeError:
        logger.warning(f"Unicode decode error in {smali_file_path}, trying binary mode")
        try:
            # Try with binary mode and decode line by line
            with open(smali_file_path, mode="rb") as f:
                for line in f:
                    try:
                        line_str = line.decode('utf-8', errors='ignore').strip()
                        # Apply the same regex pattern
                        if line_str and not line_str.startswith('.') and not line_str.startswith('#'):
                            match = re.match(r'^\s*([a-z-]+)(?:/|\s|$)', line_str)
                            if match:
                                opcode = match.group(1)
                                if opcode not in ['nop', 'label', 'line', 'parameter', 'local', 'restart', 'annotation',
                                                  'end', 'catch', 'catchall', 'prologue', 'epilogue', 'registers', 
                                                  'locals', 'array-data', 'method', 'end', 'sparse-switch-data',
                                                  'packed-switch-data', 'field', 'subannotation']:
                                    base_opcode = opcode.split('/')[0]
                                    opcodes.append(base_opcode)
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Error processing {smali_file_path} in binary mode: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing {smali_file_path}: {str(e)}")
    
    return opcodes

def process_apk_to_symbols(apk_path):
    """
    Process APK to extract symbol sequence
    
    Args:
        apk_path: Path to the APK file
    
    Returns:
        List of symbols, or None if failed
    """
    # Verify APK first
    if not verify_apk(apk_path):
        logger.warning(f"APK verification failed for {apk_path}")
        return None
    
    # Extract APK to temp directory
    temp_dir = extract_dex_to_temp(apk_path)
    if not temp_dir:
        logger.warning(f"Failed to extract {apk_path}")
        return None
    
    try:
        all_opcodes = []
        
        # Find all smali directories (including smali_classes2, smali_classes3, etc.)
        smali_dirs = []
        for item in os.listdir(temp_dir):
            if item.startswith("smali"):
                smali_dirs.append(os.path.join(temp_dir, item))
        
        if not smali_dirs:
            logger.warning(f"No smali directories found in {temp_dir}")
            return None
        
        logger.info(f"Found {len(smali_dirs)} smali directories")
        
        # Walk through all smali files in all smali directories
        total_smali_files = 0
        processed_smali_files = 0
        for smali_dir in smali_dirs:
            for root, dirs, files in os.walk(smali_dir):
                for file in files:
                    if file.endswith(".smali"):
                        total_smali_files += 1
                        smali_file_path = os.path.join(root, file)
                        try:
                            opcodes = extract_opcodes_from_smali(smali_file_path)
                            if opcodes:
                                all_opcodes.extend(opcodes)
                                processed_smali_files += 1
                        except Exception as e:
                            logger.warning(f"Error processing {smali_file_path}: {str(e)}")
        
        logger.info(f"Processed {processed_smali_files}/{total_smali_files} smali files")
        
        if not all_opcodes:
            logger.warning(f"No opcodes found in {apk_path}")
            return None
        
        logger.info(f"Extracted {len(all_opcodes)} opcodes")
        
        # Map opcodes to symbols
        symbols = map_opcodes_to_symbols(all_opcodes)
        
        logger.info(f"Mapped to {len(symbols)} symbols")
        
        return symbols
        
    except Exception as e:
        logger.error(f"Error processing {apk_path}: {str(e)}")
        return None
    
    finally:
        # Always clean up temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def map_opcodes_to_symbols(opcodes):
    """
    Map opcodes to their symbolic representation
    
    Args:
        opcodes: List of opcodes
    
    Returns:
        List of symbols
    """
    symbols = []
    
    for opcode in opcodes:
        # Find matching opcode in the mapping
        symbol = None
        for prefix, sym in OPCODE_SYMBOLS.items():
            if opcode.startswith(prefix):
                symbol = sym
                break
        
        # If no match is found, use 'X' as default
        if symbol is None:
            symbol = 'X'
        
        symbols.append(symbol)
    
    return symbols

def process_apks(input_dir, output_dir, skip_existing=True):
    """
    Process APKs in the input directory and save symbol files to output directory.
    
    Args:
        input_dir: Directory containing APK files
        output_dir: Directory to save symbol files
        skip_existing: Skip APKs that have already been processed
    
    Returns:
        A DataFrame with hash-to-label mappings
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    problematic_apks_file = os.path.join(output_dir, "problematic_apks.txt")
    
    # Dictionary to store hash-to-label mappings
    hash_to_label = {}
    
    # Get list of APK files
    apk_files = [f for f in os.listdir(input_dir) if f.endswith('.apk') and not f.startswith('._')]
    logger.info(f"Found {len(apk_files)} APK files in {input_dir}")
    
    # Track already processed files
    processed_files = set()
    if skip_existing:
        # Check the main output directory for existing .cat files
        if os.path.exists(output_dir):
            for file in os.listdir(output_dir):
                if file.endswith('.cat'):
                    processed_files.add(file.split('.')[0])
        logger.info(f"Found {len(processed_files)} already processed files (to skip)")
    
    # Process each APK
    processed_count = 0
    skipped_count = 0
    failed_count = 0
    
    for apk_file in tqdm(apk_files, desc="Processing APKs to 17-category symbols"):
        apk_path = os.path.join(input_dir, apk_file)
        apk_hash = apk_file.split('.')[0]
        
        # Skip if already processed
        if skip_existing and apk_hash in processed_files:
            logger.info(f"Skipping {apk_file} (already processed)")
            skipped_count += 1
            continue
        
        # Determine label based on directory
        is_malware = 'malware' in input_dir.lower()
        
        # Process APK to symbols
        symbols = process_apk_to_symbols(apk_path)
        
        if symbols:
            # Save symbol sequence to file with .cat extension in main output directory
            cat_file = os.path.join(output_dir, f"{apk_hash}.cat")
            with open(cat_file, 'w') as f:
                f.write(''.join(symbols))
            
            # Store label mapping
            hash_to_label[apk_hash] = 1 if is_malware else 0
            processed_count += 1
        else:
            logger.error(f"Failed to process {apk_file}")
            with open(problematic_apks_file, 'a') as f:
                f.write(f"{apk_hash},{apk_path}\n")
            failed_count += 1
    
    logger.info(f"\nProcessing summary:")
    logger.info(f"  Processed: {processed_count}")
    logger.info(f"  Skipped: {skipped_count}")
    logger.info(f"  Failed: {failed_count}")
    logger.info(f"  Total APKs: {len(apk_files)}")
    
    # Create DataFrame from hash-to-label mappings
    df = pd.DataFrame(list(hash_to_label.items()), columns=['hash', 'label'])
    
    # Save to CSV
    csv_path = os.path.join(output_dir, "hash_to_label.csv")
    
    # If CSV already exists, append to it
    if os.path.exists(csv_path):
        existing_df = pd.read_csv(csv_path)
        # Remove duplicate hashes (keep new ones)
        existing_df = existing_df[~existing_df['hash'].isin(df['hash'])]
        # Combine DataFrames
        df = pd.concat([existing_df, df], ignore_index=True)
    
    # Save to CSV
    df.to_csv(csv_path, index=False)
    logger.info(f"Saved hash-to-label mappings to {csv_path}")
    
    return df

def check_dependencies():
    """
    Check if required tools are installed
    
    Returns:
        True if all dependencies are available, False otherwise
    """
    dependencies = ["apktool", "baksmali"]
    missing = []
    
    for tool in dependencies:
        try:
            result = subprocess.run(f"which {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                missing.append(tool)
        except Exception:
            missing.append(tool)
    
    if missing:
        logger.error(f"Missing dependencies: {', '.join(missing)}")
        logger.error("Missing required dependencies. Install:")
        logger.error("  - apktool: https://ibotpeaches.github.io/Apktool/install/")
        logger.error("  - baksmali: https://github.com/JesusFreke/smali")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description="Process APKs and extract opcode symbols")
    parser.add_argument("--input", type=str, required=True, help="Input directory containing APKs")
    parser.add_argument("--output", type=str, required=True, help="Output directory to save symbol files")
    parser.add_argument("--no-skip", action="store_true", help="Don't skip already processed APKs")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Process APKs
    process_apks(
        args.input, 
        args.output, 
        skip_existing=not args.no_skip
    )

if __name__ == "__main__":
    main()