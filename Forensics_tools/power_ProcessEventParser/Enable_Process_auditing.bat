# Enable both success and failure logging
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable only success logging (recommended for less noise)
auditpol /set /subcategory:"Process Creation" /success:enable

# Verify the setting
auditpol /get /subcategory:"Process Creation"
