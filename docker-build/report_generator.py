
import os
import json
import csv
import shutil
import re
from datetime import datetime

def generate_report(directory):
    report_dir = directory
    # if not os.path.exists(report_dir):
    #     os.makedirs(report_dir)

    # Copy assets if we had any, but for now we will embed CSS/JS
    
    # Read Data
    data = {}
    
    # 1. Domains
    domain_list_path = os.path.join(directory, "domain_list.txt")
    if os.path.exists(domain_list_path):
        with open(domain_list_path, "r") as f:
            data["domains"] = [line.strip() for line in f.readlines()]
    else:
        data["domains"] = []

    # 2. IPs and Owners
    ip_json_path = os.path.join(directory, "domain_and_IP_list.json")
    if os.path.exists(ip_json_path):
        with open(ip_json_path, "r") as f:
            data["ip_map"] = json.load(f)
    else:
        data["ip_map"] = {}

    # 3. Subdomain Distribution
    subdomain_dist_path = os.path.join(directory, "subdomain_distribution.csv")
    data["subdomain_stats"] = []
    if os.path.exists(subdomain_dist_path):
        with open(subdomain_dist_path, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    data["subdomain_stats"].append({"domain": row[0], "count": row[1]})

    # 3.5 IP Ranges and Owners
    ip_ranges_path = os.path.join(directory, "IP_ranges_and_owners.txt")
    data["ip_stats"] = []
    if os.path.exists(ip_ranges_path):
        with open(ip_ranges_path, "r") as f:
            lines = f.readlines()
            # Skip header if it exists (starts with Owner)
            start_idx = 0
            if lines and "Owner" in lines[0] and "Percentage" in lines[0]:
                start_idx = 1
            
            for line in lines[start_idx:]:
                parts = line.split('|')
                if len(parts) >= 3:
                    owner = parts[0].strip()
                    percentage = parts[1].strip()
                    ranges = parts[2].strip()
                    data["ip_stats"].append({
                        "owner": owner,
                        "percentage": percentage,
                        "ranges": ranges
                    })

    # 4. Technologies
    tech_stats_path = os.path.join(directory, "technologies_statistics.json")
    if os.path.exists(tech_stats_path):
        with open(tech_stats_path, "r") as f:
            data["technologies"] = json.load(f)
    else:
        data["technologies"] = {}

    # 5. WAF
    waf_results_path = os.path.join(directory, "waf_results.json")
    if os.path.exists(waf_results_path):
        with open(waf_results_path, "r") as f:
            data["waf"] = json.load(f)
    else:
        data["waf"] = {}

    # 6. Nuclei
    nuclei_path = os.path.join(directory, "Nuclei", "nuclei_important_findings.json")
    if os.path.exists(nuclei_path):
        with open(nuclei_path, "r") as f:
            data["nuclei"] = json.load(f)
    else:
        data["nuclei"] = {}

    # 7. GAU (Get All Urls)
    gau_path = os.path.join(directory, "gau_url_findings.txt")
    if os.path.exists(gau_path):
        with open(gau_path, "r") as f:
            # Read lines and filter out empty ones
            data["gau"] = [line.strip() for line in f.readlines() if line.strip()]
    else:
        data["gau"] = []

    # 8. Screenshots
    screenshots_dir = os.path.join(directory, "Screenshots", "screens")
    source_dir = os.path.join(directory, "Screenshots", "source")
    data["screenshots"] = []
    
    if os.path.exists(screenshots_dir):
        # Get list of source files if available
        source_files = []
        if os.path.exists(source_dir):
            source_files = [f for f in os.listdir(source_dir) if f.endswith('.txt')]

        for filename in os.listdir(screenshots_dir):
            if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                # Try to find matching source file(s)
                # Screenshot: domain.com.png or http.domain.com.png
                # Source: http.domain.com.txt or https.domain.com.txt
                
                base_name = os.path.splitext(filename)[0]
                # Remove protocol prefix if present in screenshot name to match against source
                # But source files usually HAVE protocol prefix.
                
                # Strategy: Find source files that contain the base_name (minus protocol if needed)
                # If screenshot is 'google.com.png', base is 'google.com'. Source 'http.google.com.txt' matches.
                
                matches = []
                for src in source_files:
                    # Check if the screenshot base name is part of the source filename
                    # This is a loose match but should work for EyeWitness naming conventions
                    if base_name in src:
                        matches.append(src)
                
                if not matches:
                    # If no matches found, maybe the screenshot has http. prefix and source has http. prefix
                    # Just add the screenshot without source info
                    data["screenshots"].append({
                        "image": filename,
                        "source": None,
                        "title": "No Title"
                    })
                else:
                    # For each match (e.g. http and https versions), add an entry
                    for src in matches:
                        title = "Unknown Title"
                        try:
                            with open(os.path.join(source_dir, src), 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                                if title_match:
                                    title = title_match.group(1).strip()
                        except Exception:
                            pass
                            
                        data["screenshots"].append({
                            "image": filename,
                            "source": src,
                            "title": title
                        })

    # Generate HTML
    html_content = create_html(data)
    
    with open(os.path.join(report_dir, "report.html"), "w") as f:
        f.write(html_content)
    
    print(f"Report generated at {os.path.join(report_dir, 'report.html')}")

def create_html(data):
    # Basic CSS for a dark theme "hacker" style but clean
    css = """
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #e2e8f0;
            --accent-color: #38bdf8;
            --border-color: #334155;
            --success: #22c55e;
            --warning: #eab308;
            --danger: #ef4444;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        h1, h2, h3 {
            color: var(--accent-color);
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background-color: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent-color);
        }
        .stat-label {
            color: #94a3b8;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        th {
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--accent-color);
        }
        tr:hover {
            background-color: rgba(255, 255, 255, 0.02);
        }
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; }
        .badge-high { background-color: rgba(234, 179, 8, 0.2); color: #eab308; }
        .badge-medium { background-color: rgba(59, 130, 246, 0.2); color: #3b82f6; }
        .badge-low { background-color: rgba(34, 197, 94, 0.2); color: #22c55e; }
        
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .tab-btn {
            padding: 10px 20px;
            background: none;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s;
        }
        .tab-btn:hover {
            color: var(--text-color);
        }
        .tab-btn.active {
            color: var(--accent-color);
            border-bottom: 2px solid var(--accent-color);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .screenshot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
        }
        .screenshot-item img {
            width: 100%;
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }
        .screenshot-item p {
            margin-top: 5px;
            font-size: 0.9rem;
            color: #94a3b8;
            word-break: break-all;
        }
        .search-bar {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            border-radius: 4px;
            box-sizing: border-box;
        }
    </style>
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
                tabcontent[i].classList.remove("active");
            }
            tablinks = document.getElementsByClassName("tab-btn");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.className += " active";
        }
        
        function searchTable(inputId, tableId) {
            var input, filter, table, tr, td, i, txtValue;
            input = document.getElementById(inputId);
            filter = input.value.toUpperCase();
            table = document.getElementById(tableId);
            tr = table.getElementsByTagName("tr");
            for (i = 1; i < tr.length; i++) {
                var found = false;
                var tds = tr[i].getElementsByTagName("td");
                for(var j=0; j<tds.length; j++){
                    if(tds[j]){
                        txtValue = tds[j].textContent || tds[j].innerText;
                        if (txtValue.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                if (found) {
                    tr[i].style.display = "";
                } else {
                    tr[i].style.display = "none";
                }
            }
        }
    </script>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reconnaissance Report</title>
        {css}
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Reconnaissance Report</h1>
                <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </header>

            <div class="dashboard-grid">
                <div class="card">
                    <div class="stat-number">{len(data.get("domains", []))}</div>
                    <div class="stat-label">Domains Found</div>
                </div>
                <div class="card">
                    <div class="stat-number">{len({ip for info in data.get("ip_map", {}).values() for ip in info.get("ips", [])})}</div>
                    <div class="stat-label">Unique IPs</div>
                </div>
                <div class="card">
                    <div class="stat-number">{len(data.get("technologies", {}))}</div>
                    <div class="stat-label">Technologies Detected</div>
                </div>
                <div class="card">
                    <div class="stat-number">{sum(len(v) for k, v in data.get("nuclei", {}).items() if isinstance(v, list))}</div>
                    <div class="stat-label">Nuclei Findings</div>
                </div>
                <div class="card">
                    <div class="stat-number">{len(data.get("gau", []))}</div>
                    <div class="stat-label">Discovered URLs</div>
                </div>
                <div class="card">
                    <div class="stat-number">{len(data.get("screenshots", []))}</div>
                    <div class="stat-label">Screenshots</div>
                </div>
            </div>

            <div class="tabs">
                <button class="tab-btn active" onclick="openTab(event, 'domains')">Domains & IPs</button>
                <button class="tab-btn" onclick="openTab(event, 'technologies')">Technologies</button>
                <button class="tab-btn" onclick="openTab(event, 'nuclei')">Vulnerabilities</button>
                <button class="tab-btn" onclick="openTab(event, 'gau')">URLs</button>
                <button class="tab-btn" onclick="openTab(event, 'waf')">WAF</button>
                <button class="tab-btn" onclick="openTab(event, 'screenshots')">Screenshots</button>
                <button class="tab-btn" onclick="openTab(event, 'statistics')">Statistics</button>
            </div>

            <div id="domains" class="tab-content active">
                <div class="card">
                    <h3>Domains and IP Information</h3>
                    <input type="text" id="domainSearch" onkeyup="searchTable('domainSearch', 'domainTable')" class="search-bar" placeholder="Search domains...">
                    <table id="domainTable">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Source</th>
                                <th>IPs</th>
                                <th>Owner / CIDR</th>
                            </tr>
                        </thead>
                        <tbody>
    """
    
    # Populate Domains Table
    for domain, info in data.get("ip_map", {}).items():
        ips = ", ".join(info.get("ips", []))
        owner_info = info.get("Owner_Info", {})
        owner = owner_info.get("Owner", "N/A")
        cidr = info.get("CIDR", "N/A")
        source = info.get("source", "N/A")
        
        html += f"""
                            <tr>
                                <td>{domain}</td>
                                <td>{source}</td>
                                <td>{ips}</td>
                                <td>{owner} <br><small>{cidr}</small></td>
                            </tr>
        """
    
    html += """
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="technologies" class="tab-content">
                <div class="card">
                    <h3>Detected Technologies</h3>
                    <table id="techTable">
                        <thead>
                            <tr>
                                <th>Technology</th>
                                <th>Count</th>
                                <th>Versions</th>
                            </tr>
                        </thead>
                        <tbody>
    """
    
    # Populate Technologies Table
    for tech, info in data.get("technologies", {}).items():
        count = info.get("number", 0)
        versions = ", ".join(set(info.get("versions", [])))
        if not versions:
            versions = "-"
            
        html += f"""
                            <tr>
                                <td>{tech}</td>
                                <td>{count}</td>
                                <td>{versions}</td>
                            </tr>
        """

    html += """
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="nuclei" class="tab-content">
                <div class="card">
                    <h3>Nuclei Findings</h3>
    """
    
    # Populate Nuclei Findings
    nuclei_data = data.get("nuclei", {})
    severities = ["critical", "high", "medium", "low", "other"]
    
    for severity in severities:
        findings = nuclei_data.get(severity, [])
        if findings:
            html += f"""
                    <h4 style="text-transform: capitalize; margin-top: 20px;">{severity} ({len(findings)})</h4>
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 100px;">Severity</th>
                                <th style="width: 200px;">Template</th>
                                <th>URL</th>
                                <th>Info</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for finding in findings:
                # Parse finding
                # Pattern: [template-id] [protocol] [severity] url [info]
                match = re.match(r'^\[(.*?)\] \[(.*?)\] \[(.*?)\] (\S+)(.*)$', finding)
                
                if match:
                    template_id = match.group(1)
                    # protocol = match.group(2)
                    # sev_from_line = match.group(3)
                    url = match.group(4)
                    info = match.group(5).strip()
                    
                    html += f"""
                            <tr>
                                <td><span class="badge badge-{severity}">{severity}</span></td>
                                <td>{template_id}</td>
                                <td><a href="{url}" target="_blank" style="color: var(--accent-color); text-decoration: none;">{url}</a></td>
                                <td style="word-break: break-all; font-family: monospace; font-size: 0.85rem;">{info}</td>
                            </tr>
                    """
                else:
                    html += f"""
                            <tr>
                                <td><span class="badge badge-{severity}">{severity}</span></td>
                                <td colspan="3">{finding}</td>
                            </tr>
                    """
            html += """
                        </tbody>
                    </table>
            """
            
    if not any(nuclei_data.get(s) for s in severities):
        html += "<p>No significant vulnerabilities found.</p>"

    html += """
                </div>
            </div>

            <div id="gau" class="tab-content">
                <div class="card">
                    <h3>Discovered URLs (GAU)</h3>
                    <input type="text" id="gauSearch" onkeyup="searchTable('gauSearch', 'gauTable')" class="search-bar" placeholder="Search URLs...">
                    <div style="max-height: 600px; overflow-y: auto;">
                        <table id="gauTable">
                            <thead>
                                <tr>
                                    <th>URL</th>
                                </tr>
                            </thead>
                            <tbody>
    """
    
    # Populate GAU Table
    # Limit to first 2000 to prevent browser crash if huge, or just dump all?
    # Let's dump all but warn if huge. For now, just dump all.
    for url in data.get("gau", []):
        html += f"""
                                <tr>
                                    <td><a href="{url}" target="_blank" style="color: var(--text-color); text-decoration: none;">{url}</a></td>
                                </tr>
        """

    html += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="waf" class="tab-content">
                <div class="card">
                    <h3>WAF Detection</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>WAF Name</th>
                                <th>Count</th>
                                <th>URLs</th>
                            </tr>
                        </thead>
                        <tbody>
    """
    
    # Populate WAF Table
    waf_results = data.get("waf", {}).get("results", {})
    for waf_name, info in waf_results.items():
        count = info.get("counter", 0)
        urls = info.get("urls", [])
        # Limit URLs display if too many
        urls_display = "<br>".join(urls[:5])
        if len(urls) > 5:
            urls_display += f"<br>...and {len(urls)-5} more"
            
        html += f"""
                            <tr>
                                <td>{waf_name}</td>
                                <td>{count}</td>
                                <td>{urls_display}</td>
                            </tr>
        """

    html += """
                        </tbody>
                    </table>
                </div>
            </div>

            <div id="screenshots" class="tab-content">
                <div class="card">
                    <h3>Screenshots</h3>
                    <div class="screenshot-grid">
    """
    
    # Populate Screenshots
    for item in data.get("screenshots", []):
        image = item.get("image")
        source = item.get("source")
        title = item.get("title")
        
        source_link = ""
        if source:
            source_link = f'<br><a href="Screenshots/source/{source}" target="_blank" style="font-size: 0.8rem; color: var(--accent-color);">View Source</a>'
            
        html += f"""
                        <div class="screenshot-item">
                            <a href="Screenshots/screens/{image}" target="_blank">
                                <img src="Screenshots/screens/{image}" alt="{image}" loading="lazy">
                            </a>
                            <p><strong>{title}</strong><br>{image}{source_link}</p>
                        </div>
        """
        
    if not data.get("screenshots"):
        html += "<p>No screenshots available.</p>"

    html += """
                    </div>
                </div>
            </div>

            <div id="statistics" class="tab-content">
                <div class="dashboard-grid">
                    <div class="card">
                        <h3>Subdomain Distribution</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Root Domain</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
    """
    for item in data.get("subdomain_stats", []):
        html += f"""
                                <tr>
                                    <td>{item['domain']}</td>
                                    <td>{item['count']}</td>
                                </tr>
        """
    html += """
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="card">
                        <h3>IP Ranges & Owners</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Owner</th>
                                    <th>Percentage</th>
                                    <th>Ranges</th>
                                </tr>
                            </thead>
                            <tbody>
    """
    for item in data.get("ip_stats", []):
        html += f"""
                                <tr>
                                    <td>{item['owner']}</td>
                                    <td>{item['percentage']}</td>
                                    <td>{item['ranges']}</td>
                                </tr>
        """
    html += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>
    </body>
    </html>
    """
    return html