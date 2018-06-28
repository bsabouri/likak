import magic
import pefile
import logging


class FileType(object):
    """this module provides info about file type"""
    def __init__(self, file):
        super(FileType, self).__init__()

        self.ftyp = None
        self.arch = None
        self.file = file
        self.mt = {'0x14c': 'x86', '0x8664': 'x64'}
        self.typs = {'pe': 'application/x-dosexec',
                     'flash': 'application/x-shockwave-flash',
                     'pdf': 'application/pdf',
                     'word': ['application/msword',
                             'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
                     'excel': ['application/vnd.ms-excel',
                              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
                     }

    def machine_type(self, pe):
        machine_type = pe.FILE_HEADER.Machine
        if type(machine_type) is int:
            return self.mt[str(hex(machine_type))]

    def pe_check(self, file):
        pe = pefile.PE(file)
        if not (pe.is_exe() or pe.is_dll()):
            logging.info('PE file is not exe or dll')
            return False
        self.arch = self.machine_type(pe)
        if pe.is_exe():
            self.ftyp = 'exe'
        elif pe.is_dll():
            self.ftyp = 'dll'
        return self.ftyp, self.arch

    def word_check(self, file_type, key):
        if key in file_type:
            self.ftyp = 'doc'
        else:
            self.ftyp = 'docx'
        return self.ftyp, self.arch

    def excel_check(self, file_type, key):
        if key in file_type:
            self.ftyp = 'xls'
        else:
            self.ftyp = 'xlsx'
        return self.ftyp, self.arch

    def check_flash(self):
        # todo: specify flash files
        self.ftyp = 'flash'
        return self.ftyp, self.arch

    def run(self):
        ftyp = magic.from_file(self.file, mime=True)
        if any(ftyp in typ for typ in self.typs.values()):

            major_type = [major_type for major_type, mime in self.typs.items() if ftyp in mime][0]

            if major_type == 'pe':
                self.pe_check(self.file)
                
            elif major_type == 'word':
                self.word_check(ftyp, key='msword')
            elif major_type == 'excel':
                self.excel_check(ftyp, key='ms-excel')
            elif major_type == 'flash':
                self.check_flash()
            elif major_type == 'pdf':
                self.ftyp = 'pdf'
            return self.ftyp, self.arch
        else:
            logging.info('%s (type: %s) is not a supported file format!' % (self.file, ftyp))
            return self.ftyp, self.arch
