#!/usr/bin/env

import base64
import jasypt4py
import MySQLdb
import sys
import os

from MySQLdb import cursors
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding

class TerminalFormatting:
  HEADER    = '\x1B[95m'
  OKBLUE    = '\x1B[94m'
  OKGREEN   = '\x1B[92m'
  WARNING   = '\x1B[93m'
  ERROR     = '\x1B[91m'
  ENDC      = '\x1B[0m'
  BOLD      = '\x1B[1m'
  UNDERLINE = '\x1B[4m'

class JamfPro:
  def __init__(self, db_host, db_name, db_user, db_pass):

    # There are hard-coded in the Jamf Pro software (PasswordServiceImpl.class and PasswordServiceImpl$Encrypter.class)
    self.storage_key  = '2M#84->)y^%2kGmN97ZLfhbL|-M:j?'
    self.salt         = b'\xA9\x9B\xC8\x32\x56\x35\xE3\x03'
    self.iterations   = 19

    # Set database config
    self.db_host      = db_host
    self.db_name      = db_name
    self.db_user      = db_user
    self.db_pass      = db_pass

    # Initialize variables
    self.session_key  = None
    self.db_cursor    = None

  def initialize(self):

    # Create a database connection
    print_info(
      'Connecting to database'
    )

    try:
      self.db=MySQLdb.connect(
        user=self.db_user,
        passwd=self.db_pass,
        db=self.db_name,
        host=self.db_host,
        cursorclass=cursors.DictCursor
      )
    
    except MySQLdb.OperationalError as e:
      print_error(
        'Database connection failed: {0}'.format(e),
        exit_code=1
      )

    print_success(
      'Connected to database "{0}"'.format(
        self.db_name
      )
    )

    # Get a cursor
    self.db_cursor = self.db.cursor()

    # Get the decrypted session key
    print_info(
      'Getting session key'
    )

    self.session_key = self.get_session_key()

    print_success(
      'Got session key "{0}"'.format(self.session_key)
    )

  def get_session_key(self):

    # Get encrypted session key from database
    self.db_cursor.execute(
      'SELECT FROM_BASE64(encryption_key), encryption_type FROM encryption_key;'
    )

    # See if it's there
    if self.db_cursor.rowcount != 1:
      print_error(
        'Error getting session key',
        exit_code=2
      )

    result = self.db_cursor.fetchone()

    # Check if it's AES
    encryption_method = result['encryption_type']
    if encryption_method != 1:
      print_error(
        'Unsupported encryption method',
        exit_code=3
      )

    # Decrypt the session key
    enc_session_key = result['FROM_BASE64(encryption_key)']

    session_key = self.decrypt(
      enc_session_key,
      self.storage_key
    )

    return session_key

  def decrypt(self, cipher_text, password=None):
    
    if not password:
      password = self.session_key.decode("utf-8")

    # Generate key and IV
    generator = jasypt4py.generator.PKCS12ParameterGenerator(SHA256)
    key, iv = generator.generate_derived_parameters(password, self.salt, self.iterations)

    # Do actual decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
      plain_text = Padding.unpad(cipher.decrypt(cipher_text), AES.block_size)
    except IndexError:
      plain_text = cipher.decrypt(cipher_text)

    # Return decrypted data
    return plain_text

def print_success(s):
  sys.stdout.write(
    '{0}[+]{1} {2}\n'.format(
      TerminalFormatting.OKGREEN,
      TerminalFormatting.ENDC,
      s
    ) 
  )
  sys.stdout.flush()

def print_error(s, exit=True, exit_code=100):
  sys.stderr.write(
    '{0}[!]{1} {2}\n'.format(
      TerminalFormatting.ERROR,
      TerminalFormatting.ENDC,
      s
    ) 
  )
  sys.stdout.flush()

  if exit:
    sys.exit(exit_code)

def print_info(s):
  sys.stdout.write(
    '{0}[-]{1} {2}\n'.format(
      TerminalFormatting.OKBLUE,
      TerminalFormatting.ENDC,
      s
    ) 
  )
  sys.stdout.flush()

def get_css():
  css = """
    <style type="text/css">
      tbody th {
          border: 1px solid #000;
      }
      tbody td {
          border: 1px solid #ababab;
          border-spacing: 0px;
          padding: 4px;
          border-collapse: collapse;
          overflow: hidden;
          text-overflow: ellipsis;
          max-width: 200px;
      }
      body {
          font-family: verdana;
      }
      table {
          font-size: 13px;
          border-collapse: collapse;
          width: 100%;
      }
      tbody tr:nth-child(odd) td {
          background-color: #eee;
      }
      tbody tr:hover td {
          background-color: lightblue;
      }
    </style>
  """
  return css

def dump_data(jamf):
  jamf.db_cursor.execute(
    'SHOW tables'
  )

  tables = [row['Tables_in_{}'.format(jamf.db_name)] for row in jamf.db_cursor.fetchall()]
  for table in tables:
    jamf.db_cursor.execute(
      'SHOW COLUMNS FROM {}'.format(
        table
      )
    )
    if jamf.db_cursor.rowcount > 0:
      columns = [row['Field'] for row in jamf.db_cursor]    
      # Check if this table is worth spending time on
      for column in columns:
        CONTAINS_ENCRYPTED_DATA = False
        if column.endswith('_encrypted'):
          CONTAINS_ENCRYPTED_DATA = True
          break

      if not CONTAINS_ENCRYPTED_DATA:
        continue
      else:
        jamf.db_cursor.execute(
          'SELECT * FROM {}'.format(
            table
          )
        ) 
        print_info(
          'Found encrypted data in table "{0}", decrypting..'.format(
            table
          )
        )

      html_filename = '{0}.html'.format(
        os.path.basename(table)
      )

      with open(html_filename, 'w') as html_file:
        
        html_file.write(
          '<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset="UTF-8">\n\t{0}</head>\n\t<body>\n\t\t<table>\n\t\t\t<tbody>\n\t\t\t\t<tr>\n'.format(
            get_css()
          )
        )

        for column in columns:
          
          if column.endswith('_encrypted'):
            html_file.write(
             '\t\t\t\t\t<th>{0}</th>\n'.format(
                column.replace(
                  '_encrypted', '_decrypted'
                )
              )
            )
          else:
            html_file.write(
            '\t\t\t\t\t<th>{0}</th>\n'.format(
              column
            )
          )


        html_file.write(
          '\t\t\t\t</tr>\n'
        )

        for row in jamf.db_cursor:
          html_file.write(
            '\t\t\t\t<tr>\n'
          )

          for column in columns:

            if column.endswith('_encrypted'):
              html_file.write(
               '\t\t\t\t\t<td>{0}</td>\n'.format(
                  jamf.decrypt(base64.b64decode(row[column]))
                )
              )
            else:
              try:
                html_file.write(
                  '\t\t\t\t\t<td>{0}</td>\n'.format(
                    str(row[column])
                  )
                )
              except UnicodeDecodeError:
                html_file.write(
                  '\t\t\t\t\t<td>{0}</td>\n'.format(
                    row[column].encode('hex')
                  )
                )

          html_file.write(
            '\t\t\t\t</tr>\n'
          )

        html_file.write(
          "\t\t\t</tbody>\n\t\t</table>\n\t</body>\n</html>"
        ) 

def main():

  jamf = JamfPro(
    db_host='127.0.0.1',
    db_name='jamf',
    db_user='jamf',
    db_pass='jamf'
  )

  jamf.initialize()

  dump_data(
    jamf
  )

if __name__ == '__main__':
  main()
