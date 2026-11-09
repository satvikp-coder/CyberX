# CyberX: Phishing Website Detector

A machine-learning web app that checks whether a website looks like phishing. Built for the IBM Z Datathon 2025.

![Python](https://img.shields.io/badge/language-Python-3776AB?style=flat-square)
![Status](https://img.shields.io/badge/status-hackathon%20prototype-orange?style=flat-square)

## What it does

- Takes website features and predicts phishing or legitimate.
- Uses a trained classifier saved in `website_classifier.joblib`.
- Has a simple web front end (`frontend.html`, `backend.js`) and a Python app (`app.py`).

## How to run

```bash
git clone https://github.com/satvikp-coder/CyberX.git
cd CyberX
pip install -r requirements.txt
python app.py
```

See `Instruction.txt` for more notes.

## Results and limits

[TODO: ask Satvik: accuracy or other metrics, and how the model was tested]. No results are claimed here.

## Status

Hackathon prototype (October 2025). Duplicate copies exist in `CyberX.github.io` and an empty `CyberX.com` repo; consider archiving them.

## License

MIT. See `LICENSE`.
