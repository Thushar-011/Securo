```markdown  
# Securo - Password Manager  [1](#header-1)
  
A secure password manager built with Django and MySQL featuring zero-knowledge encryption. [4-cite-0](#4-cite-0)   
  
## Features  [2](#header-2)
  
- **Zero-Knowledge Encryption**: AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation [4-cite-1](#4-cite-1)   
- **Two-Factor Authentication**: Optional TOTP-based 2FA [4-cite-2](#4-cite-2)   
- **Password Security**: Breach detection via HaveIBeenPwned API [4-cite-3](#4-cite-3)   
- **Data Portability**: CSV import/export [4-cite-4](#4-cite-4)   
  
## Tech Stack  [3](#header-3)
  
- Django 5.2.8 [4-cite-5](#4-cite-5)   
- MySQL  
- AES-256 encryption [4-cite-6](#4-cite-6)   
- pyotp for 2FA [4-cite-2](#4-cite-2)   
  
## Installation  [4](#header-4)
  
1. Clone the repository  
2. Install dependencies:  
   ```bash  
   pip install -r requirements.txt  
   ```  
3. Configure `.env` file with database credentials  
4. Run migrations:  
   ```bash  
   python manage.py migrate  
   ```  
5. Start server:  
   ```bash  
   python manage.py runserver  
   ```  
  
## Security  [5](#header-5)
  
- Session-based encryption key management [4-cite-7](#4-cite-7)   
- Per-user encryption salts<cite />  
- Field-level encryption for sensitive data<cite />  
  
## License  [6](#header-6)
  
MIT License  
```
