import ssl
import socket
import smtplib
import json
import requests
from datetime import datetime
from email.mime.text import MIMEText
from ssl import SSLCertVerificationError
from email.mime.multipart import MIMEMultipart
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse

class SSLCertChecker:
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password, recipients):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipients = recipients
        self.failed_certificates = []

    @classmethod
    def from_config_file(cls, config_path):
        with open(config_path, "r") as file:
            config = json.load(file)
        return cls(
            config["smtp_server"],
            config["smtp_port"],
            config["sender_email"],
            config["sender_password"],
            config["recipients"]
        )

    def is_resolvable(self, hostname):
        try:
            socket.gethostbyname(hostname)
            return True
        except socket.gaierror:
            return False

    def normalize_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"

    def check_url_variants(self, domain):
        error_messages = []
        if self.is_resolvable(domain):
            redirect_url = None
            protocols = ['https://', 'http://']
            for proto in protocols:
                original_url = proto + domain
                try:
                    response = requests.get(original_url, allow_redirects=True, timeout=5)
                    final_url = response.url
                    if 200 <= response.status_code < 300:
                        if self.normalize_url(final_url) == self.normalize_url(original_url):
                            print(f"[VALID] {original_url} -> {final_url} -> {response.status_code}")
                            return final_url, None
                        else:
                            msg = f"[REDIRECT 200-300] {original_url} -> {final_url} -> {response.status_code}"
                            print(msg)
                            error_messages.append(msg)
                            redirect_url = final_url
                    elif 300 <= response.status_code < 400:
                        msg = f"[REDIRECT 300-400] {original_url} -> {final_url} -> {response.status_code}"
                        print(msg)
                        error_messages.append(msg)
                        redirect_url = final_url
                    else:
                        msg = f"[INVALID] Status: {response.status_code} for {original_url}"
                        print(msg)
                        error_messages.append(msg)
                except requests.exceptions.RequestException as e:
                    msg = f"[ERROR] {proto} failed: {str(e)}"
                    print(msg)
                    error_messages.append(msg)

            if redirect_url:
                return None, redirect_url

            self.failed_certificates.append({
                "hostname": domain,
                "error": " | ".join(error_messages)
            })
            return None, None
        else:
            msg = f"[DNS ERROR] {domain} could not be resolved."
            print(msg)
            self.failed_certificates.append({
                "hostname": domain,
                "error": msg
            })
            return None, None

    def get_certificate_info(self, hostname, port=443):
        if not self.is_resolvable(hostname):
            error_message = f"[DNS ERROR] {hostname} could not be resolved."
            print(f"❌ {hostname}:{port} ➜ {error_message}")
            self.failed_certificates.append({"hostname": hostname, "error": error_message})
            return None

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(5.0)

        try:
            conn.connect((hostname, port))
            der_cert = conn.getpeercert(binary_form=True)
        except SSLCertVerificationError as e:
            error_message = f"[SSL CERT VERIFY ERROR] {e}"
            print(f"❌ {hostname}:{port} ➜ {error_message}")
            self.failed_certificates.append({"hostname": hostname, "error": error_message})
            return None
        except socket.gaierror as e:
            error_message = f"[CONNECTION ERROR] {e}"
            print(f"❌ {hostname}:{port} ➜ {error_message}")
            self.failed_certificates.append({"hostname": hostname, "error": error_message})
            return None
        except Exception as e:
            error_message = f"[CONNECTION ERROR] {e}"
            print(f"❌ {hostname}:{port} ➜ {error_message}")
            self.failed_certificates.append({"hostname": hostname, "error": error_message})
            return None
        finally:
            conn.close()

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        days_left = (not_after - datetime.utcnow()).days

        return {
            "hostname": hostname,
            "subject": subject,
            "issuer": issuer,
            "valid_from": not_before.strftime('%Y-%m-%d'),
            "valid_until": not_after.strftime('%Y-%m-%d'),
            "days_left": days_left
        }

    def generate_html_table(self, cert_data, failed_data):
        expiring_rows = ""
        for cert in cert_data:
            color = "red" if cert["days_left"] < 30 else "orange"
            expiring_rows += f"""
                <tr>
                    <td style=\"color:{color}\">{cert['hostname']}</td>
                    <td style=\"color:{color}\">{cert['subject']}</td>
                    <td style=\"color:{color}\">{cert['issuer']}</td>
                    <td style=\"color:{color}\">{cert['valid_from']}</td>
                    <td style=\"color:{color}\">{cert['valid_until']}</td>
                    <td style=\"color:{color}\">{cert['days_left']}</td>
                </tr>
            """

        failed_rows = ""
        for item in failed_data:
            failed_rows += f"""
                <tr>
                    <td>{item['hostname']}</td>
                    <td style=\"color:red\">{item['error']}</td>
                </tr>
            """

        return f"""
        <html>
        <head>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                h3 {{ margin-top: 30px; }}
            </style>
        </head>
        <body>
            <h3>⚠️ SSL Certificate Expiry in Days</h3>
            <table>
                <tr>
                    <th>Hostname</th>
                    <th>Subject</th>
                    <th>Issuer</th>
                    <th>Valid From</th>
                    <th>Valid Until</th>
                    <th>Days Left</th>
                </tr>
                {expiring_rows or '<tr><td colspan="6">✅ No expiring certificates</td></tr>'}
            </table>

            <h3>❌ Failed SSL Checks</h3>
            <table>
                <tr>
                    <th>Hostname</th>
                    <th>Error</th>
                </tr>
                {failed_rows or '<tr><td colspan="2">✅ No failures</td></tr>'}
            </table>
        </body>
        </html>
        """

    def send_email(self, html_content):
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "🔒 SSL Certificate Expiry Alert"
        msg["From"] = self.sender_email
        msg["To"] = ", ".join(self.recipients)

        part = MIMEText(html_content, "html")
        msg.attach(part)

        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.sendmail(self.sender_email, self.recipients, msg.as_string())

    def check_and_notify(self, host_file="host.txt"):
        expiring_certificates = []
        checked_hosts = set()
        checked_cert_targets = set()

        try:
            with open(host_file, "r") as file:
                for line in file:
                    hostname = line.strip()
                    if not hostname or hostname in checked_hosts:
                        continue
                    checked_hosts.add(hostname)

                    print(f"\n🔎 Checking: {hostname}")
                    valid_url, redirected_url = self.check_url_variants(hostname)

                    cert_target = None
                    if valid_url:
                        cert_target = urlparse(valid_url).hostname
                    elif redirected_url:
                        cert_target = urlparse(redirected_url).hostname

                    if cert_target and cert_target not in checked_cert_targets:
                        checked_cert_targets.add(cert_target)
                        cert_info = self.get_certificate_info(cert_target)
                        if cert_info:
                            expiring_certificates.append(cert_info)

        except FileNotFoundError:
            print(f"❌ Host file '{host_file}' not found.")
            return [], []

        if expiring_certificates or self.failed_certificates:
            html = self.generate_html_table(expiring_certificates, self.failed_certificates)
            self.send_email(html)

        return expiring_certificates, self.failed_certificates


if __name__ == "__main__":
    checker = SSLCertChecker.from_config_file("config.json")
    expiring, failed = checker.check_and_notify("hostnames.txt")

    print(f"\n🔒 Expiring Certificates: {len(expiring)}")
    for cert in expiring:
        print(f"  - {cert['hostname']} ➜ {cert['days_left']} days left")

    print(f"\n❌ Failed to Fetch: {len(failed)}")
    for fail in failed:
        print(f"  - {fail['hostname']} ➜ {fail['error']}")
