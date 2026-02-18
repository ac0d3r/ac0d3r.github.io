## 前提

上一篇[文章](https://blog.imipy.com/post/find-slider-captcha-position-with-opencv-template-matching.html)介绍了使用`Template Matching`定位到缺口位置，再模拟鼠标去滑动元素就可以了。
但是我遇到一个有趣的案例：

![Image](https://github.com/user-attachments/assets/9ee83179-06b5-4aa1-888e-9af04769170f)

如这个视频所示，滑块和拼图的移动关系并非线性：先慢、再均速、最后快。但它们之间肯定存在某种数学关系。

## 采集数据

在浏览器上使用JS采集滑块和拼图两个元素对应的移动数据（style:`left:xxpx`）：

```javascript
const slider = document.querySelector('#captcha-sliding-slider');
const puzzle = document.querySelector('#captcha-puzzle');

let recordedData = [];
let sliderObserver = null;

function recordPositions() {
    if (!slider || !puzzle) return;

    const slider_x = parseFloat(slider.style.left) || 0;
    const puzzle_x = parseFloat(puzzle.style.left) || 0;

    recordedData.push({
        slider_x: slider_x,
        puzzle_x: puzzle_x,
    });
}

document.addEventListener('mousedown', () => {
    if (!slider) return;

    recordedData = [];
    sliderObserver = new MutationObserver(recordPositions);
    sliderObserver.observe(slider, { attributes: true, attributeFilter: ['style'] });
});

document.addEventListener('mouseup', () => {
    if (sliderObserver) {
        sliderObserver.disconnect();
        sliderObserver = null;
        console.log(`记录完成: ${recordedData.length} 条`);
    }
});

function exportToCSV() {
    if (recordedData.length === 0) return;

    const headers = ['Slider_Left(px)', 'Puzzle_Left(px)'];
    const csvRows = [headers.join(',')];

    recordedData.forEach(row => {
        csvRows.push([
            row.slider_x,
            row.puzzle_x,
        ].join(','));
    });

    const blob = new Blob(['\ufeff' + csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `positions_${Date.now()}.csv`;
    link.click();
}

function viewData() {
    console.table(recordedData);
}
```

## 推算公式

使用AI帮我推算出公式：

<img width="829" height="389" alt="Image" src="https://github.com/user-attachments/assets/2bae2f16-bae8-4fa4-b93b-680fbe02ebee" />

```python
def calculate_puzzle_x(slider_x):
    """从 slider_x 计算 puzzle_x（优化浮点精度）"""
    # 使用 Horner 方法重写多项式，减少浮点误差
    # 原式: -0.0000020625 + 0.0769232487*x + 0.0035502933*x² + 0.000000000006490*x³
    # Horner: -0.0000020625 + x*(0.0769232487 + x*(0.0035502933 + x*(0.000000000006490)))
    result = -0.0000020625 + slider_x * (0.0769232487 + slider_x * (0.0035502933 + slider_x * (0.000000000006490)))
    return round(result, 2)
```

## 生成逆公式

还是使用AI生成逆公式，根据 puzzle_x 距离计算出 slider_x 实际要拖动的距离：

```python
def calculate_slider_x(puzzle_x, initial_guess=None):
    """
    从 puzzle_x 计算 slider_x（逆函数 - 最高精度）
    使用牛顿迭代法从精确公式反推，优化浮点精度
    
    参数:
        puzzle_x: 目标 puzzle_x 值
        initial_guess: 初始猜测值（可选，默认使用 puzzle_x 作为初始值）
    
    返回:
        slider_x: 计算出的 slider_x 值
    """
    # 初始猜测：使用 puzzle_x 作为起点（通常接近真实值）
    x = initial_guess if initial_guess is not None else puzzle_x
    
    # 牛顿迭代法求解方程：calculate_puzzle_x(x) - puzzle_x = 0
    tolerance = 1e-12  # 提高收敛精度
    max_iterations = 100
    
    for i in range(max_iterations):
        # f(x) = calculate_puzzle_x(x) - puzzle_x
        fx = calculate_puzzle_x(x) - puzzle_x
        
        if abs(fx) < tolerance:
            return round(x, 2)
        
        # f'(x) = 导数，使用 Horner 方法优化
        # 原式: 0.0769232487 + 2*0.0035502933*x + 3*0.000000000006490*x²
        # Horner: 0.0769232487 + x*(2*0.0035502933 + x*3*0.000000000006490)
        fpx = 0.0769232487 + x * (0.0071005866 + x * (0.00000000001947))
        
        if abs(fpx) < 1e-15:  # 避免除以零
            break
        
        # 牛顿迭代：x_new = x - f(x)/f'(x)
        x_new = x - fx / fpx
        
        # 检查收敛（相对变化）
        if abs(x_new - x) < tolerance * (1.0 + abs(x)):
            return round(x_new, 2)
        
        x = x_new
    
    return round(x, 2)
```
