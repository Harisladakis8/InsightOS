from flask import Flask, request, jsonify, Blueprint, current_app
from flask_cors import CORS
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS
import os
import tempfile
import json
from datetime import datetime
import hashlib
import mimetypes

# Δημιούργησε το Blueprint
app_file = Blueprint('file_app', __name__)
CORS(app_file)

def extract_gps_info(gps_info):
    """Εξάγει και μετατρέπει GPS δεδομένα σε αναγνώσιμη μορφή."""
    if not gps_info:
        return None
    
    gps_data = {}
    
    for key in gps_info.keys():
        tag_name = GPSTAGS.get(key, f"GPS_{key}")
        value = gps_info[key]
        
        # Μετατροπή GPS συντεταγμένων
        if tag_name == "GPSLatitude":
            gps_data["latitude"] = convert_gps_coordinates(value, gps_info.get(3, 'N'))
            gps_data["latitude_raw"] = str(value)
        elif tag_name == "GPSLongitude":
            gps_data["longitude"] = convert_gps_coordinates(value, gps_info.get(4, 'E'))
            gps_data["longitude_raw"] = str(value)
        elif tag_name == "GPSAltitude":
            gps_data["altitude"] = str(value[0]) + " m" if isinstance(value, tuple) else str(value)
        elif tag_name == "GPSTimeStamp":
            gps_data["gps_time"] = format_gps_time(value)
        elif tag_name == "GPSDateStamp":
            gps_data["gps_date"] = str(value)
        elif tag_name == "GPSLatitudeRef":
            gps_data["latitude_ref"] = str(value)
        elif tag_name == "GPSLongitudeRef":
            gps_data["longitude_ref"] = str(value)
        else:
            gps_data[tag_name] = str(value)
    
    # Δημιουργία Google Maps link αν έχουμε συντεταγμένες
    if "latitude" in gps_data and "longitude" in gps_data:
        lat = gps_data["latitude"]
        lon = gps_data["longitude"]
        gps_data["google_maps_link"] = f"https://www.google.com/maps?q={lat},{lon}"
        gps_data["openstreetmap_link"] = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"
    
    return gps_data

def format_gps_time(time_tuple):
    """Μορφοποίηση GPS χρόνου."""
    try:
        if isinstance(time_tuple, tuple) and len(time_tuple) == 3:
            hours = int(time_tuple[0])
            minutes = int(time_tuple[1])
            seconds = int(time_tuple[2])
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    except:
        pass
    return str(time_tuple)

def convert_gps_coordinates(coords, ref):
    """Μετατρέπει GPS συντεταγμένες σε δεκαδική μορφή."""
    try:
        if isinstance(coords, tuple) and len(coords) == 3:
            degrees = float(coords[0])
            minutes = float(coords[1])
            seconds = float(coords[2])
            
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            
            # Προσαρμογή βάσει κατεύθυνσης
            if ref in ['S', 'W']:
                decimal = -decimal
            
            return round(decimal, 6)
    except:
        pass
    return str(coords)

def get_critical_metadata(exif_data):
    """Εξάγει τα πιο σημαντικά metadata για προτεραιοποίηση."""
    critical = {
        "camera_info": {},
        "location_info": {},
        "date_time_info": {},
        "technical_info": {},
        "copyright_info": {}
    }
    
    if not exif_data:
        return critical
    
    # Κατηγορίες σημαντικών tags
    critical_tags = {
        "camera_info": [
            'Make', 'Model', 'LensMake', 'LensModel', 'SerialNumber', 
            'BodySerialNumber', 'Software', 'Artist'
        ],
        "location_info": [
            'GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSDateStamp',
            'GPSTimeStamp'
        ],
        "date_time_info": [
            'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
            'SubSecTime', 'SubSecTimeOriginal'
        ],
        "technical_info": [
            'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'FocalLength',
            'ExposureProgram', 'MeteringMode', 'Flash', 'WhiteBalance',
            'DigitalZoomRatio', 'SceneCaptureType', 'Sharpness',
            'Contrast', 'Saturation', 'BrightnessValue'
        ],
        "copyright_info": [
            'Copyright', 'ImageDescription', 'UserComment'
        ]
    }
    
    # Εξαγωγή και οργάνωση
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")
        
        for category, tags in critical_tags.items():
            if tag_name in tags:
                # Ειδική επεξεργαση για ορισμένες τιμές
                if tag_name == 'ExposureTime':
                    try:
                        if isinstance(value, tuple):
                            value = f"1/{int(1/value[0]/value[1])}" if value[0] < 1 else str(value[0])
                    except:
                        pass
                elif tag_name == 'FNumber':
                    try:
                        if isinstance(value, tuple):
                            value = f"f/{value[0]/value[1]:.1f}"
                    except:
                        pass
                elif tag_name == 'FocalLength':
                    try:
                        if isinstance(value, tuple):
                            value = f"{value[0]/value[1]:.0f}mm"
                    except:
                        pass
                
                critical[category][tag_name] = str(value)
                break
    
    return critical

def detect_device_type(make, model):
    """Ανιχνεύει τον τύπο συσκευής βάσει make/model."""
    if not make or not model:
        return "Unknown"
    
    make_lower = str(make).lower()
    model_lower = str(model).lower()
    
    # Smartphones
    if 'apple' in make_lower or 'iphone' in model_lower:
        return "Apple iPhone"
    elif 'samsung' in make_lower or 'galaxy' in model_lower:
        return "Samsung Galaxy"
    elif 'google' in make_lower or 'pixel' in model_lower:
        return "Google Pixel"
    elif 'xiaomi' in make_lower or 'redmi' in model_lower or 'poco' in model_lower:
        return "Xiaomi/Redmi/Poco"
    elif 'huawei' in make_lower or 'honor' in model_lower:
        return "Huawei/Honor"
    elif 'oneplus' in make_lower:
        return "OnePlus"
    elif 'oppo' in make_lower:
        return "Oppo"
    elif 'vivo' in make_lower:
        return "Vivo"
    elif 'realme' in make_lower:
        return "Realme"
    elif 'sony' in make_lower and 'xperia' in model_lower:
        return "Sony Xperia"
    
    # Cameras
    elif 'canon' in make_lower:
        return "Canon Camera"
    elif 'nikon' in make_lower:
        return "Nikon Camera"
    elif 'sony' in make_lower and 'dsc' in model_lower:
        return "Sony Camera"
    elif 'fujifilm' in make_lower:
        return "Fujifilm Camera"
    elif 'panasonic' in make_lower or 'lumix' in model_lower:
        return "Panasonic/Lumix"
    elif 'olympus' in make_lower:
        return "Olympus Camera"
    elif 'leica' in make_lower:
        return "Leica Camera"
    elif 'gopro' in make_lower:
        return "GoPro Action Camera"
    elif 'dji' in make_lower:
        return "DJI Drone"
    
    # Λοιπά
    elif 'windows' in make_lower:
        return "Windows Device"
    elif 'android' in make_lower:
        return "Android Device"
    
    return f"{make} {model}"

def analyze_security_risks(basic_info, gps_data, critical_metadata):
    """Ανάλυση ασφαλείας και προτάσεις."""
    risks = []
    recommendations = []
    security_level = "🟢 Ασφαλής"
    
    # Έλεγχος για GPS
    if gps_data:
        risks.append("📍 Περιέχει GPS συντεταγμένες")
        recommendations.append("Αφαίρεσε τα GPS δεδομένα πριν διαμοιραστείς την εικόνα")
        security_level = "🟡 Προσοχή"
    
    # Έλεγχος για προσωπικές πληροφορίες
    if critical_metadata.get('copyright_info', {}).get('Copyright'):
        risks.append("©️ Περιέχει πληροφορίες πνευματικών δικαιωμάτων")
    
    if critical_metadata.get('camera_info', {}).get('SerialNumber'):
        risks.append("🔢 Περιέχει σειριακό αριθμό κάμερας")
        recommendations.append("Κρύψε τον σειριακό αριθμό για ανωνυμία")
        security_level = "🟡 Προσοχή"
    
    # Έλεγχος για λεπτομέρειες τοποθεσίας
    if 'Model' in critical_metadata.get('camera_info', {}):
        model = critical_metadata['camera_info']['Model']
        if any(word in str(model).lower() for word in ['iphone', 'galaxy', 'pixel']):
            risks.append("📱 Αποκαλύπτει μοντέλο κινητού")
    
    # Αν δεν υπάρχουν ρίσκοι
    if not risks:
        risks.append("✅ Δεν εντοπίστηκαν σημαντικοί κίνδυνοι")
        recommendations.append("Η εικόνα είναι σχετικά ασφαλής για διαμοίραση")
    
    return {
        "security_level": security_level,
        "risks": risks,
        "recommendations": recommendations,
        "summary": f"{len(risks)} ζητήματα ασφαλείας εντοπίστηκαν"
    }

@app_file.route('/api/metadata/upload', methods=['POST'])
def upload_metadata():
    """Endpoint για ανέβασμα αρχείου και εξαγωγή ΠΙΟ ΣΗΜΑΝΤΙΚΩΝ μεταδεδομένων."""
    try:
        upload_folder = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
        
        if 'file' not in request.files:
            return jsonify({
                "success": False,
                "error": "Δεν ανεβάστηκε αρχείο",
                "status": "error"
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "Δεν επιλέχθηκε αρχείο",
                "status": "error"
            }), 400
        
        # Έλεγχος τύπος αρχείου
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'heic', 'jfif'}
        if '.' in file.filename:
            extension = file.filename.rsplit('.', 1)[1].lower()
            if extension not in allowed_extensions:
                return jsonify({
                    "success": False,
                    "error": f"Μη υποστηριζόμενος τύπος αρχείου",
                    "status": "error"
                }), 400
        
        # Αποθήκευση προσωρινά
        temp_path = os.path.join(upload_folder, file.filename)
        file.save(temp_path)
        
        try:
            with Image.open(temp_path) as img:
                # Βασικές πληροφορίες
                file_stats = os.stat(temp_path)
                mime_type, _ = mimetypes.guess_type(temp_path)
                
                basic_info = {
                    # Βασικά
                    "filename": file.filename,
                    "file_extension": extension if '.' in file.filename else "unknown",
                    "mime_type": mime_type or "unknown",
                    "file_size_mb": round(file_stats.st_size / (1024 * 1024), 2),
                    
                    # Διαστάσεις
                    "dimensions": f"{img.size[0]} × {img.size[1]} pixels",
                    "width": img.size[0],
                    "height": img.size[1],
                    "aspect_ratio": f"{img.size[0]}:{img.size[1]}",
                    "megapixels": round((img.size[0] * img.size[1]) / 1000000, 2),
                    
                    # Τεχνικά
                    "format": img.format or "Unknown",
                    "color_mode": img.mode,
                    "has_alpha": 'A' in img.mode,
                    
                    # Χρονικά
                    "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "file_created": datetime.fromtimestamp(file_stats.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "file_modified": datetime.fromtimestamp(file_stats.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # EXIF δεδομένα
                exif_raw = img._getexif() or {}
                critical_metadata = get_critical_metadata(exif_raw)
                
                # GPS δεδομένα
                gps_data = {}
                if 34853 in exif_raw:  # GPSInfo tag ID
                    gps_data = extract_gps_info(exif_raw[34853])
                
                # Ανίχνευση συσκευής
                make = critical_metadata['camera_info'].get('Make', '')
                model = critical_metadata['camera_info'].get('Model', '')
                device_type = detect_device_type(make, model)
                
                # Ασφάλεια
                security_analysis = analyze_security_risks(basic_info, gps_data, critical_metadata)
                
                # Καθαρισμός προσωρινού αρχείου
                try:
                    os.remove(temp_path)
                except:
                    pass
                
                # ΟΡΓΑΝΩΣΗ ΤΕΛΙΚΩΝ ΑΠΟΤΕΛΕΣΜΑΤΩΝ - ΠΙΟ ΣΗΜΑΝΤΙΚΑ ΠΡΩΤΑ
                results = {
                    # 1. ΣΥΝΟΠΤΙΚΗ ΑΝΑΛΥΣΗ (πιο σημαντικό)
                    "overview": {
                        "device": device_type,
                        "dimensions": basic_info["dimensions"],
                        "file_size": f"{basic_info['file_size_mb']} MB",
                        "format": basic_info["format"],
                        "security": security_analysis["security_level"],
                        "has_gps": bool(gps_data),
                        "has_exif": len(exif_raw) > 0
                    },
                    
                    # 2. ΚΑΜΕΡΑ & ΣΥΣΚΕΥΗ (πολύ σημαντικό)
                    "camera_device": {
                        "make": make,
                        "model": model,
                        "device_type": device_type,
                        "software": critical_metadata['camera_info'].get('Software', 'N/A'),
                        "lens": critical_metadata['camera_info'].get('LensModel', 'N/A'),
                        "serial": critical_metadata['camera_info'].get('SerialNumber', 'N/A')
                    },
                    
                    # 3. ΡΥΘΜΙΣΕΙΣ ΚΑΜΕΡΑΣ (τεχνικά σημαντικά)
                    "camera_settings": {
                        "exposure": critical_metadata['technical_info'].get('ExposureTime', 'N/A'),
                        "aperture": critical_metadata['technical_info'].get('FNumber', 'N/A'),
                        "iso": critical_metadata['technical_info'].get('ISOSpeedRatings', 'N/A'),
                        "focal_length": critical_metadata['technical_info'].get('FocalLength', 'N/A'),
                        "flash": critical_metadata['technical_info'].get('Flash', 'N/A'),
                        "white_balance": critical_metadata['technical_info'].get('WhiteBalance', 'N/A')
                    },
                    
                    # 4. ΧΡΟΝΟΣ & ΗΜΕΡΟΜΗΝΙΑ
                    "date_time": {
                        "captured": critical_metadata['date_time_info'].get('DateTimeOriginal', 
                                  critical_metadata['date_time_info'].get('DateTime', 'N/A')),
                        "digitized": critical_metadata['date_time_info'].get('DateTimeDigitized', 'N/A'),
                        "file_created": basic_info["file_created"],
                        "file_modified": basic_info["file_modified"]
                    },
                    
                    # 5. ΤΟΠΟΘΕΣΙΑ (GPS) - αν υπάρχει
                    "location": gps_data if gps_data else {"status": "Δεν βρέθηκαν GPS δεδομένα"},
                    
                    # 6. ΑΣΦΑΛΕΙΑ & ΠΡΟΤΑΣΕΙΣ
                    "security": security_analysis,
                    
                    # 7. ΒΑΣΙΚΑ ΤΕΧΝΙΚΑ
                    "technical": {
                        "resolution": f"{basic_info['width']}x{basic_info['height']}",
                        "megapixels": basic_info["megapixels"],
                        "color_mode": basic_info["color_mode"],
                        "has_alpha_channel": basic_info["has_alpha"],
                        "aspect_ratio": basic_info["aspect_ratio"]
                    },
                    
                    # 8. ΠΝΕΥΜΑΤΙΚΑ ΔΙΚΑΙΩΜΑΤΑ
                    "copyright": {
                        "copyright": critical_metadata['copyright_info'].get('Copyright', 'N/A'),
                        "artist": critical_metadata['camera_info'].get('Artist', 'N/A'),
                        "description": critical_metadata['copyright_info'].get('ImageDescription', 'N/A')
                    },
                    
                    # 9. ΠΛΗΡΗ ΔΕΔΟΜΕΝΑ (για προχωρημένους)
                    "full_data": {
                        "basic_info": basic_info,
                        "all_exif_count": len(exif_raw),
                        "has_additional_data": len(exif_raw) > 0
                    }
                }
                
                # Δημιουργία συνοπτικού μηνύματος
                summary_parts = []
                if device_type != "Unknown":
                    summary_parts.append(f"📷 {device_type}")
                
                summary_parts.append(f"📐 {basic_info['dimensions']}")
                summary_parts.append(f"💾 {basic_info['file_size_mb']} MB")
                
                if gps_data:
                    summary_parts.append("📍 Με GPS")
                
                summary_message = " | ".join(summary_parts)
                
                return jsonify({
                    "success": True,
                    "results": results,
                    "summary": summary_message,
                    "priority_data": {
                        "device": device_type,
                        "dimensions": basic_info["dimensions"],
                        "has_gps": bool(gps_data),
                        "security_level": security_analysis["security_level"],
                        "capture_date": results["date_time"]["captured"]
                    },
                    "status": "success",
                    "timestamp": datetime.now().isoformat()
                })
                
        except Exception as img_error:
            try:
                os.remove(temp_path)
            except:
                pass
            
            return jsonify({
                "success": False,
                "error": f"Σφάλμα επεξεργασίας εικόνας: {str(img_error)}",
                "status": "error"
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Σφάλμα διακομιστή: {str(e)}",
            "status": "error"
        }), 500

@app_file.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "Priority Metadata Extractor",
        "version": "3.0",
        "features": [
            "Priority-based metadata extraction",
            "Device type detection",
            "Security risk analysis",
            "GPS coordinate conversion",
            "Camera settings extraction",
            "Organized by importance"
        ],
        "priority_categories": [
            "1. Overview & Device",
            "2. Camera & Settings",
            "3. Date & Time",
            "4. Location (GPS)",
            "5. Security Analysis",
            "6. Technical Details",
            "7. Copyright Info"
        ]
    })

@app_file.route('/api/metadata/sample', methods=['GET'])
def sample_metadata():
    """Επιστρέφει δείγμα metadata δομής για testing."""
    return jsonify({
        "success": True,
        "sample_structure": {
            "overview": {
                "device": "Apple iPhone 13 Pro",
                "dimensions": "3024 × 4032 pixels",
                "file_size": "4.2 MB",
                "format": "JPEG",
                "security": "🟡 Προσοχή",
                "has_gps": True,
                "has_exif": True
            },
            "camera_device": {
                "make": "Apple",
                "model": "iPhone 13 Pro",
                "device_type": "Apple iPhone",
                "software": "16.1.1",
                "lens": "iPhone 13 Pro back triple camera 6mm f/1.5",
                "serial": "F2LPA0A1G5MV"
            },
            "camera_settings": {
                "exposure": "1/120",
                "aperture": "f/1.5",
                "iso": "125",
                "focal_length": "26mm",
                "flash": "No Flash",
                "white_balance": "Auto"
            }
        }
    })