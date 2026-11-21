import os
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont

def create_brand_templates(output_dir: str):
    """
    Creates reference brand logo templates for visual comparison.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Google (Blue, Red, Yellow, Green colors)
    img_google = Image.new('RGB', (240, 80), color=(255, 255, 255))
    draw = ImageDraw.Draw(img_google)
    # Simple colorful text representation
    draw.rectangle([10, 10, 230, 70], outline=(66, 133, 244), width=3)
    draw.text((25, 25), "Google", fill=(66, 133, 244))
    img_google.save(os.path.join(output_dir, "google.png"))

    # 2. PayPal (Navy & Sky Blue double P)
    img_paypal = Image.new('RGB', (240, 80), color=(255, 255, 255))
    draw = ImageDraw.Draw(img_paypal)
    draw.rectangle([10, 10, 230, 70], fill=(0, 48, 135))
    draw.text((30, 25), "PayPal", fill=(0, 121, 193))
    img_paypal.save(os.path.join(output_dir, "paypal.png"))

    # 3. Microsoft (4-square colors: Red, Green, Blue, Yellow)
    img_ms = Image.new('RGB', (240, 80), color=(255, 255, 255))
    draw = ImageDraw.Draw(img_ms)
    # 4 squares
    draw.rectangle([20, 20, 45, 45], fill=(242, 80, 34)) # Red
    draw.rectangle([50, 20, 75, 45], fill=(127, 186, 0)) # Green
    draw.rectangle([20, 50, 45, 75], fill=(0, 164, 239)) # Blue
    draw.rectangle([50, 50, 75, 75], fill=(255, 185, 0)) # Yellow
    draw.text((90, 30), "Microsoft", fill=(115, 115, 115))
    img_ms.save(os.path.join(output_dir, "microsoft.png"))

    # 4. Amazon (Black text with curved Orange smile)
    img_amz = Image.new('RGB', (240, 80), color=(255, 255, 255))
    draw = ImageDraw.Draw(img_amz)
    draw.rectangle([10, 10, 230, 70], fill=(35, 47, 62)) # Dark navy
    draw.text((30, 25), "amazon", fill=(255, 255, 255))
    draw.arc([30, 45, 160, 65], start=0, end=180, fill=(255, 153, 0), width=3)
    img_amz.save(os.path.join(output_dir, "amazon.png"))

    # 5. Netflix (Black background, bold Red text)
    img_nflx = Image.new('RGB', (240, 80), color=(20, 20, 20))
    draw = ImageDraw.Draw(img_nflx)
    draw.rectangle([10, 10, 230, 70], outline=(229, 9, 20), width=2)
    draw.text((35, 25), "NETFLIX", fill=(229, 9, 20))
    img_nflx.save(os.path.join(output_dir, "netflix.png"))

if __name__ == '__main__':
    target_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'brand_logos')
    create_brand_templates(target_dir)
    print("Created brand logo templates in:", target_dir)
