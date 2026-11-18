PhishTrace - Email Phishing Triage and Analysis Tool



1.Project Overview



PhishTrace is a Python-based email phishing triage tool that analyzes `.eml` files to identify suspicious email characteristics. It combines email parsing, header analysis, URL and domain extraction, SPF/DKIM/DMARC evidence assessment, and VirusTotal reputation lookups into a consolidated JSON investigation report.



The tool is designed as an academic cybersecurity project and investigation aid. It does not automatically declare an email malicious based on a single indicator.

2.Problem Statement



Phishing emails commonly use misleading sender information, unusual reply addresses, suspicious links, and authentication failures to deceive recipients. Manually inspecting these characteristics can be time-consuming.



PhishTrace aims to automate initial email inspection and organize relevant findings into a structured report, helping an analyst decide which emails require further investigation.

3.Objectives



\- Parse email messages from `.eml` files.

\- Analyze sender, Reply-To, and other email-header characteristics.

\- Extract URLs and associated domains from email bodies.

\- Examine available SPF, DKIM, and DMARC authentication evidence.

\- Query existing VirusTotal reports for extracted URLs and domains.

\- Generate a consolidated JSON investigation report.

\- Handle missing API keys, unavailable reports, and API errors safely.

4.Technologies Used



\- \*\*Programming language:\*\* Python

\- \*\*Email processing:\*\* Python standard email libraries

\- \*\*HTTP requests:\*\* Requests

\- \*\*External reputation source:\*\* VirusTotal API v3

\- \*\*Output format:\*\* JSON

\- \*\*Testing:\*\* Python unittest framework

\- \*\*Development environment:\*\* Windows 11 and PowerShell



5.System Modules



\### Email Parser

Reads an `.eml` file and extracts sender, recipient, subject, message identifiers, headers, and message content.



\### Header Analyzer

Checks for potentially suspicious header characteristics, including sender and Reply-To domain mismatches. It also records when Received or Authentication-Results headers are absent.



\### IOC Extractor

Extracts URLs and hostnames from email body text. Extracted indicators are not automatically considered malicious.



\### Authentication Analyzer

Reports SPF, DKIM, and DMARC evidence available in the supplied email headers. These results are not independently authenticated by the tool.



\### VirusTotal Reputation Module

Queries existing VirusTotal URL and domain reports using an API key supplied through the `VT\_API\_KEY` environment variable. It does not submit the email file or visit extracted URLs.



\### Investigation Engine

Combines module outputs, produces a preliminary triage assessment, and saves the consolidated report as JSON.



6.Workflow



1\. The analyst supplies an `.eml` file.

2\. PhishTrace parses the email and its headers.

3\. The header analyzer identifies relevant findings.

4\. The IOC extractor identifies URLs and domains.

5\. The authentication analyzer evaluates available authentication evidence.

6\. The reputation module queries existing VirusTotal records.

7\. The investigation engine combines the results and writes a JSON report.



7.Project Structure



```text

PhishTrace/

├── src/

│   ├── email\_parser.py

│   ├── header\_analyzer.py

│   ├── ioc\_extractor.py

│   ├── authentication.py

│   ├── reputation.py

│   └── phishtrace.py

├── samples/

│   ├── benign/

│   └── suspicious/

├── tests/

│   ├── test\_header\_analyzer.py

│   ├── test\_ioc\_extractor.py

│   ├── test\_authentication.py

│   └── test\_reputation.py

├── reports/

├── docs/

├── requirements.txt

└── README.md

```



8.Installation and Execution



Create and activate a virtual environment:



```powershell

python -m venv .venv

.\\.venv\\Scripts\\Activate.ps1

```



Install dependencies:



```powershell

python -m pip install -r requirements.txt

```



Configure the VirusTotal API key in the current PowerShell session:



```powershell

$env:VT\_API\_KEY = "YOUR\_API\_KEY"

```



Run an investigation:



```powershell

python .\\src\\phishtrace.py .\\samples\\suspicious\\sample\_phishing.eml

```



The report is generated at:



```text

reports/investigation\_report.json

```



9.Testing



The VirusTotal reputation module has four unit tests covering:



\- Missing API key

\- Missing VirusTotal report

\- Unauthorized API key

\- API rate limiting



These tests mock API responses and do not require live VirusTotal requests. Other module scripts have also been executed against the synthetic sample. Formal automated test coverage for every module remains a future improvement.



10.Limitations



\- The tool performs initial triage and does not prove that an email is malicious.

\- Authentication results are based on supplied headers and are not independently verified.

\- Missing VirusTotal records produce an `UNKNOWN` result.

\- API access, rate limits, and report availability affect reputation results.

\- The current synthetic sample uses reserved `.test` domains, which are unsuitable for demonstrating real public-domain reputation.

\- The tool does not inspect mailbox delivery, recipient clicks, endpoint activity, or actual compromise.



11.Future Scope



\- Add formal automated tests for all modules and the complete investigation workflow.

\- Improve reputation-result interpretation and report presentation.

\- Add support for HTML email-body analysis.

\- Add configurable risk scoring with documented rationale.

\- Develop an analyst-friendly graphical interface.

\- Add safe integration with additional threat-intelligence sources.



12.Conclusion



PhishTrace demonstrates how Python can automate several initial phishing-analysis tasks and consolidate their outputs into a structured investigation report. It provides a foundation for a larger email-security analysis platform while retaining clear distinctions between suspicious indicators, missing evidence, and confirmed findings.

