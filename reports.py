import datetime
import tempfile
import os


def build_combined_results(uid):
    now = datetime.datetime.now().strftime("%Y-%m-%d")
    return {
        "uid":uid,
        "timestamp":now,
        "email":{
            "from":None,
            "subject": None,
            "date": None,
        },
        "header_analysis":{
            "checks":{

            },
        },
        "attachment":None,

    }
def render_dict(data, indent=0):
    lines =[]
    prefix = "  " *  indent
    if data is None:
        return ["*None*"]
    try:
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    lines.append(f"{prefix}- **{key}**:")
                    lines.extend(render_dict(value, indent + 1))
                else:
                    lines.append(f"{prefix}- **{key}**: {value}")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    lines.extend(render_dict(item, indent))
                else:
                    lines.append(f"{prefix}- {item}")
    except Exception as e:
        raise e
    return lines

def format_md(combined_result):
    try:
        lines = []

        lines.append("# Email Security Report")
        lines.append(f"**UID**: {combined_result['uid']}")

        lines.append("## Header Analysis")
        for check_name, check_data in combined_result["header_analysis"]["checks"].items():
            lines.append(f"### {check_name}")
            lines.extend(render_dict(check_data))
        if combined_result["attachment"] is not None:
            lines.append("## Attachment Analysis")
            lines.append(f"**Filename**: {combined_result['attachment']['file']}")

            lines.append("### Findings")
            if combined_result["attachment"]["findings"]:    
                for finding in combined_result["attachment"]["findings"]:
                    lines.append(f"- {finding}")
            else:
                lines.append("*No findings*")
            
            lines.append("### Checks")
            for check_name, check_data in combined_result["attachment"]["checks"].items():
                lines.append(f"### {check_name}")
                lines.extend(render_dict(check_data))
        else:
            lines.append("## Attachment Analysis")
            lines.append("*No attachment*")

    except Exception as e:
        raise e

    return "\n".join(lines)

def generate_report(combined_result):
    try:
        date = datetime.datetime.now().strftime("%Y-%m-%d")
        uid = combined_result["uid"]

        report_dir = os.path.join("reports", date, str(uid))
        os.makedirs(report_dir, exist_ok=True)

        report_path = os.path.join(report_dir, "report.md")

        content = format_md(combined_result)
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',suffix='.md',delete=False, dir=report_dir) as report:
            report.write(content)
            report.flush()
            temp_path = report.name
        os.rename(temp_path, report_path)
    except Exception as e:
        raise e
