# WIDS submission checklist

## Project and execution

- [x] Modular Python project and requirements file.
- [x] AWID3 offline preparation and sequence manifest.
- [x] Saved scikit-learn Decision Tree and inference dashboard.
- [x] Explicit no-live-capture/no-disruption disclosure in app and documentation.
- [x] Windows PowerShell setup, training, test, and launch commands in README.
- [ ] Student runs the app in the presentation environment and rehearses the demo.
- [ ] Student verifies course citation and dataset access/licensing terms.
- [ ] Student reviews every result and can explain the code and limitations.

## Dataset and model evidence

- [x] Prepared AWID3 window file and JSON provenance manifest retained.
- [x] Window labels and mixed-window rule documented.
- [x] Leakage-prone identifiers, chronology, source labels/counts, mixed indicator, and direct Deauth count/rate/fraction excluded from model inputs.
- [x] Preprocessing fitted inside the sklearn pipeline using training data only.
- [x] Seeded stratified random holdout; exact split size and class distributions recorded.
- [x] Accuracy, precision, recall, F1, confusion matrix, held-out predictions, and majority baseline saved.
- [ ] Do not describe the exploratory within-capture split as independent-capture validation.
- [ ] Do not claim detection of an attack flood; no flood episode ground truth/threshold was evaluated.

## Poster and demonstration

- [ ] Lay out `reports/POSTER_CONTENT.md` as an A1 poster and check legibility at print size.
- [ ] Capture a screenshot of the actual running dashboard; do not fabricate screenshots.
- [ ] Follow `DEMO_GUIDE.md` and demonstrate an offline prepared CSV.
- [ ] Explain the one false negative and limitations in your own words.
- [ ] Explain assistance and authorship according to course policy.

## Final technical checks

```powershell
python -m pytest -q
python -m compileall -q src app.py tests
```

Never include the full licensed AWID3 source files in Git. Re-run tests and review the resulting outputs before submission if code or data changes.
