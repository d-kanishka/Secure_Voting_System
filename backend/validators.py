import re

# Student pattern: cb.sc.u4cse<id>@cb.students.amrita.edu
STUDENT_RE = re.compile(r"^cb\.sc\.u4cse\d+@cb\.students\.amrita\.edu$", re.IGNORECASE)
# Admin pattern: <any>@cb.admin.amrita.edu
ADMIN_RE = re.compile(r"^.+@cb\.admin\.amrita\.edu$", re.IGNORECASE)

AUDITOR_RE = re.compile(r"^.+@cb\.auditor\.amrita\.edu$", re.IGNORECASE)

def role_from_email(email: str):

    if not email or not isinstance(email, str):
        return None
    email = email.strip()
    if STUDENT_RE.match(email):
        return "voter"
    if ADMIN_RE.match(email):
        # Admin domain maps to admin; auditors can be created by admin later
        return "admin"
    if AUDITOR_RE.match(email):
        return "auditor"
    return None