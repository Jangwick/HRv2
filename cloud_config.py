import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
from cloudinary.utils import cloudinary_url
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def configure_cloudinary():
    # Configure Cloudinary using environment variables
    cloudinary.config(
        cloud_name=os.environ.get('CLOUDINARY_CLOUD_NAME'),
        api_key=os.environ.get('CLOUDINARY_API_KEY'),
        api_secret=os.environ.get('CLOUDINARY_API_SECRET'),
        secure=True
    )

def upload_profile_image(image_file, public_id=None):
    """
    Upload an image to Cloudinary
    
    Args:
        image_file: The file object to upload
        public_id: Optional custom public ID for the image
        
    Returns:
        dict: Upload result containing URL and other info
    """
    try:
        # Configure Cloudinary if not already configured
        configure_cloudinary()
        
        # Upload parameters
        upload_params = {
            'folder': 'hr_profile_pictures',
            'overwrite': True,
            'resource_type': 'image'
        }
        
        # Use custom public_id if provided
        if public_id:
            upload_params['public_id'] = public_id
            
        # Upload the image
        result = cloudinary.uploader.upload(image_file, **upload_params)
        
        return result
    except Exception as e:
        print(f"Error uploading to Cloudinary: {e}")
        return None

def delete_profile_image(public_id):
    """
    Delete an image from Cloudinary
    
    Args:
        public_id: The public ID of the image to delete
        
    Returns:
        bool: True if deletion was successful
    """
    try:
        # Configure Cloudinary if not already configured
        configure_cloudinary()
        
        # Ensure the public_id includes the folder prefix
        if public_id and not public_id.startswith('hr_profile_pictures/'):
            full_public_id = f"hr_profile_pictures/{public_id}"
        else:
            full_public_id = public_id
        
        print(f"Attempting to delete Cloudinary image: {full_public_id}")
            
        # Delete the image
        result = cloudinary.uploader.destroy(full_public_id)
        
        if result.get('result') == 'ok':
            print(f"Successfully deleted Cloudinary image: {full_public_id}")
            return True
        else:
            print(f"Failed to delete Cloudinary image: {full_public_id}, response: {result}")
            return False
    except Exception as e:
        print(f"Error deleting image from Cloudinary: {e}")
        return False

def get_optimized_url(public_id, width=300, height=300, crop="fill", version=None):
    """
    Generate an optimized Cloudinary URL
    
    Args:
        public_id: The public ID of the image
        width: Desired width
        height: Desired height
        crop: Crop mode (fill, limit, etc.)
        version: Optional version for cache busting
        
    Returns:
        str: Optimized image URL
    """
    # Configure Cloudinary if not already configured
    configure_cloudinary()
    
    # Add folder prefix if not present
    if public_id and not public_id.startswith('hr_profile_pictures/'):
        full_public_id = f"hr_profile_pictures/{public_id}"
    else:
        full_public_id = public_id
    
    # Prepare transformation parameters
    transform_params = {
        'width': width,
        'height': height,
        'crop': crop,
        'fetch_format': "auto", 
        'quality': "auto"
    }
    
    # Add version for cache busting if provided
    if version:
        transform_params['version'] = version
    
    # Generate the optimized URL
    url, _ = cloudinary_url(full_public_id, **transform_params)
    
    return url
