// Mermaid.js loader for blog
(function () {
  if (window.__mermaidLoaderInitialized) return;
  window.__mermaidLoaderInitialized = true;

  var script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js';
  script.onload = function () {
    renderAllMermaidBlocks();
    if (window.mermaid) {
      mermaid.initialize({ startOnLoad: false });
      renderMermaidNodes();
    }
  };
  document.head.appendChild(script);

  function ensurePanZoomLoaded(callback) {
    if (window.svgPanZoom) {
      callback();
      return;
    }
    if (window.__mermaidPanZoomLoading) return;
    window.__mermaidPanZoomLoading = true;
    var panZoomScript = document.createElement('script');
    panZoomScript.src = 'https://cdn.jsdelivr.net/npm/svg-pan-zoom@3.6.1/dist/svg-pan-zoom.min.js';
    panZoomScript.onload = function () {
      window.__mermaidPanZoomLoading = false;
      callback();
    };
    document.head.appendChild(panZoomScript);
  }

  function normalizeMermaidCode(code) {
    if (!code) return '';
    return code.replace(/\r\n/g, '\n').replace(/\u00a0/g, ' ').trim();
  }

  function replacePreWithMermaid(pre) {
    if (!pre || pre.dataset.mermaidProcessed) return;
    var code = normalizeMermaidCode(pre.textContent || pre.innerText || '');
    if (!code) return;
    var container = document.createElement('div');
    container.className = 'mermaid';
    container.textContent = code;
    pre.dataset.mermaidProcessed = '1';
    pre.parentElement.replaceChild(container, pre);
  }

  function replaceCodeWithMermaid(codeElement) {
    if (!codeElement || codeElement.dataset.mermaidProcessed) return;
    if (codeElement.tagName && codeElement.tagName.toLowerCase() === 'pre') {
      replacePreWithMermaid(codeElement);
      return;
    }
    var parent = codeElement.parentElement;
    if (!parent || !parent.parentElement) return;
    var code = normalizeMermaidCode(codeElement.textContent || codeElement.innerText || '');
    if (!code) return;
    var container = document.createElement('div');
    container.className = 'mermaid';
    container.textContent = code;
    codeElement.dataset.mermaidProcessed = '1';
    parent.parentElement.replaceChild(container, parent);
  }

  function renderAllMermaidBlocks() {
    var highlightBlocks = document.querySelectorAll('div.highlight.highlight-source-mermaid > pre');
    highlightBlocks.forEach(replacePreWithMermaid);

    var blocks = document.querySelectorAll('pre code.language-mermaid, pre code.mermaid, code.language-mermaid, code.mermaid, .language-mermaid');
    blocks.forEach(replaceCodeWithMermaid);
  }

  function renderMermaidNodes() {
    var nodes = document.querySelectorAll('.mermaid');
    nodes.forEach(function (node, index) {
      if (node.dataset.mermaidRendered) return;
      var code = normalizeMermaidCode(node.textContent || node.innerText || '');
      if (!code) return;
      node.dataset.mermaidRendered = '1';
      mermaid.render('mermaid-' + index, code)
        .then(function (result) {
          node.innerHTML = result.svg;
          if (result.bindFunctions) result.bindFunctions(node);
          var svg = node.querySelector('svg');
          if (svg) {
            svg.style.width = '100%';
            svg.style.height = '100%';
            svg.style.display = 'block';
          }
          initPanZoomWhenVisible(node);
        })
        .catch(function (err) {
          node.dataset.mermaidRendered = '';
          console.error('Mermaid render failed', err, code);
        });
    });
  }

  function initPanZoomWhenVisible(node) {
    ensurePanZoomLoaded(function () {
      var svg = node.querySelector('svg');
      if (!svg || svg.dataset.panZoomApplied) return;

      var rect = svg.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        var details = node.closest('details');
        if (details && !details.open) {
          var onToggle = function () {
            if (!details.open) return;
            details.removeEventListener('toggle', onToggle);
            requestAnimationFrame(function () {
              initPanZoomWhenVisible(node);
            });
          };
          details.addEventListener('toggle', onToggle);
          return;
        }
        requestAnimationFrame(function () {
          initPanZoomWhenVisible(node);
        });
        return;
      }

      svg.dataset.panZoomApplied = '1';
      try {
        window.svgPanZoom(svg, {
          zoomEnabled: true,
          controlIconsEnabled: true,
          fit: true,
          center: true
        });
      } catch (err) {
        console.error('Mermaid pan/zoom init failed', err);
      }
    });
  }
})();
