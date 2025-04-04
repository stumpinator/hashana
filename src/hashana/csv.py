from csv import DictReader, DictWriter
from collections.abc import Iterator, Iterable

from .adapters import CSVAdapter
from .exceptions import InvalidAdapterError


class BasicCSV:
    """Basic read/write operations for a csv file"""
    
    path: str
    
    def __init__(self, path: str):
        """
        Args:
            path (str): path to CSV file where data will be read/write
        """
        self.path = path
    
    def insert_dicts(self, rows:Iterable[dict], fields:Iterable[str]) -> int:
        """Convert dictionaries into a csv file.

        Args:
            rows (Iterable[dict]): dictionary object to be written using keys for header
            fields (Iterable[str]): list of strings used to write header and pull items from dictionary

        Returns:
            int: number of lines written including header
        """
        count = 1
        with open(self.path, 'w', newline='') as csvfile:
            writer = DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
                count += 1
        return count
    
    def insert_lines(self, lines: Iterable[str], header: str = None) -> int:
        """write lines to a text file

        Args:
            lines (Iterable[str]): list of strings to be written to file
            header (str, optional): header line. Defaults to None.

        Returns:
            int: number of lines written including header
        """
        count = 0
        with open(self.path, 'wt') as csvfile:
            if header is not None:
                csvfile.write(header + '\n')
                count += 1
            for line in lines:
                csvfile.write(line + '\n')
                count += 1
        return count
    
    def enum_rows(self) -> Iterator[dict]:
        """enumerate lines in csv file as dictionaries

        Yields:
            Iterator[dict]: key = column/header name. value = line entry
        """
        with open(self.path, 'rt') as csvfile:
            data = DictReader(csvfile)
            for row in data:
                yield row
    
    def enum_column(self, column: int, header: bool = False) -> Iterator[str]:
        """enumerate individual items in a csv by column index

        Args:
            column (int): index of column/field to enumerate
            header (bool, optional): Switch to enumerate first line (the header). False will skip the first line. Defaults to False.

        Yields:
            Iterator[str]: _description_
        """
        for line in self.enum_lines(header):
            yield line.split(',')[column]
    
    def enum_field(self, fieldname: str) -> Iterator[str]:
        """enumerate individual items in a csv by the field name in header

        Args:
            fieldname (str): name of field as listed in header

        Yields:
            Iterator[str]: all values corresponding to selected field
        """
        for row in self.enum_rows():
            yield row[fieldname]
    
    def enum_lines(self, header: bool = False) -> Iterator[str]:
        """enumerates a text (csv) file line by line

        Args:
            header (bool, optional): Switch to enumerate first line (the header). False will skip the first line. Defaults to False.

        Yields:
            Iterator[str]: string for each line in file.
        """
        with open(self.path, 'rt') as f:
            x = f.readline()
            if header:
                yield x
            while row := f.readline():
                yield row


class AdaptedCSV(BasicCSV):
    """Read/writes CSV file. Requires items to implement CSVAdapter
    """
    _csv_adapter = None
    
    def __init__(self, path: str, csv_adapter: CSVAdapter):
        """
        Args:
            path (str): path to CSV file where data will be read/write
            csv_adapter (CSVAdapter): adapter class to convert to/from csv lines
        """
        if not issubclass(csv_adapter, CSVAdapter):
            raise InvalidAdapterError("Adapter must support CSVAdapter interface")
        super().__init__(path)
        self._csv_adapter = csv_adapter
        
    def insert_adapted(self, data: Iterator[CSVAdapter]):
        """insert items into CSV. clobbers existing items.

        Args:
            data (Iterator[CSVAdapter]): items to insert. must support CSVAdapter interface
        """
        with open(self.path, 'wt') as f:
            f.write(self._csv_adapter.csv_header())
            for d in data:
                f.write(d.as_csv_line())
            
    def enum_adapted(self) -> Iterator[CSVAdapter]:
        """enumerates items in the csv file

        Yields:
            Iterator[CSVAdapter]: items converted using CSVAdapter
        """
        for line in self.enum_lines():
            yield self._csv_adapter.from_csv_line(line)
            
