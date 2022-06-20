This tool crawls the Typo3 advisory list. While doing so it parses all advisories (Title, severity, affected component, ...) and dumps it into a JSON file. 

There is still room for improvement, especially for "affected versions". The main problem is the inconsistent formatting within the advisory database. Newer advisories are written differently then old ones, headings are not consistently named, and HTML elements randomly change.

However, this should get most data.

This tool was inspired by the [Typo3Scan](https://github.com/whoot/Typo3Scan) advisory crawler, as I wanted to improve that crawler and make it more robust. However, in the end that would've been to much work... The most time efficent way would probably to just create one base-database (validated by hand) for all the old Typo3 vulnerabilities, and then only crawl for new vulnerabilities (They seem to have gotten better with their formatting cconsistency).
