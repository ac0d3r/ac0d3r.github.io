## Template Matching
> [Wiki: Template_matching](https://en.wikipedia.org/wiki/Template_matching)

The technique we’ll use is called **Template Matching**. Basically, it slides a small image — the template — across a larger image, and measures how similar each region is.

[OpenCV](https://opencv.org/) provides the `cv.matchTemplate()` method, which makes Template Matching easy, You can learn more in template matching [tutorial](https://docs.opencv.org/4.x/d4/dc6/tutorial_py_template_matching.html).

## Find Slider CAPTCHA Position

```Python
def find_gap_position(background_img, template_img):
    """
    Use Template Matching to find the slider gap position
    """
    # Convert to grayscale
    bg_gray = cv2.cvtColor(background_img, cv2. COLOR_BGR2GRAY)
    template_gray = cv2.cvtColor(template_img, cv2. COLOR_BGR2GRAY)

    # Template matching
    result = cv2.matchTemplate(bg_gray, template_gray, cv2. TM_CCOEFF_NORMED)

    # Find the best match position
    _, max_val, _, max_loc = cv2.minMaxLoc(result)
    return max_loc[0], max_val  # Return x coordinate and match confidence
```

Using this pair of sample images as an example (sample1:bg&template):

<img height="150" alt="Image" src="https://github.com/user-attachments/assets/9850db1a-4fff-405f-95bf-08c466ce2baa" /><img height="150" alt="Image" src="https://github.com/user-attachments/assets/d350795b-8aa5-4c97-a729-de451d2ace23" />

```Python
background = cv2.imread("sample1-bg.png")
template = cv2.imread("sample1-template.png")

gap_x, confidence = find_gap_position(background, template)
print(
    f"Template matching result - X coordinate: {gap_x}, Confidence: {confidence:.4f}")
## Output
# Template matching result - X coordinate: 169, Confidence: 0.3312
```

Use the `verify_gap_position` function to check whether the template match position is correct:

```Python
def verify_gap_position(background, template, gap_x, save_path):
    """
    Create verification image showing the found gap position
    """
    # Create verification image: overlay template onto background image
    result_img = background.copy()
    template_height, template_width = template.shape[:2]

    # Add red border to template
    template_with_border = template.copy()
    cv2.rectangle(template_with_border, (0, 0),
                  (template_width-1, template_height-1), (0, 0, 255), 1)

    # Overlay bordered template onto background at found position
    # Use weighted blending to make template semi-transparent
    if gap_x + template_width <= background.shape[1] and template_height <= background.shape[0]:
        roi = result_img[0:template_height, gap_x:gap_x+template_width]
        # 0.85 background transparency, 0.15 template transparency
        blended = cv2.addWeighted(roi, 0.3, template_with_border, 0.7, 0)
        result_img[0:template_height, gap_x:gap_x+template_width] = blended

    # Save verification image
    cv2.imwrite(save_path, result_img)
    print(f"Verification image saved as {save_path}")
```

Verify sample1 result：

<img height="150" alt="Image" src="https://github.com/user-attachments/assets/9fc56967-2675-4866-87cb-5a3ad11e2f5f" />


## Test more samples

<img height="150" alt="Image" src="https://github.com/user-attachments/assets/04c89342-928b-4e54-a0f3-2687ae1f267d" /><img height="150" alt="Image" src="https://github.com/user-attachments/assets/318700fe-639d-4e81-949c-f2b78e44202d" />

<img height="150" alt="Image" src="https://github.com/user-attachments/assets/e2ad29ef-4865-4d7b-9055-fd1fb69908f1" />

**The recognition is very accurate**!!!