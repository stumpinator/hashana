import sqlite3
from csv import DictReader, DictWriter
from collections.abc import Iterator, Iterable
from pathlib import Path


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

class RDSReader:
    """Read and enumerate files in the NSRL Reference Data Set (RDS)"""
    
    path: Path
    sql_file_count: str = r"""SELECT COUNT(*) FROM FILE;"""
    sql_hash_count: str = r"""SELECT COUNT(*) FROM (SELECT md5 FROM FILE WHERE file_size > 0 GROUP BY md5);"""
    
    _custom_columns: frozenset = frozenset(('md5','sha1','sha256','file_size'))
    
    @staticmethod
    def dict_factory(cursor, row) -> dict:
        """row factory used with sqlite3 to return dictionaries
        
        Returns:
            dict: dictionary with key/value cooresponding to column/row
        """
        fields = [column[0] for column in cursor.description]
        return {key: value for key, value in zip(fields, row)}
    
    def __init__(self, path):
        """
        Args:
            path (str): path to NSRL RDS sqlite database
        """
        self.path = Path(path)

    def file_count(self) -> int:
        """number of entries in the FILE view.
           fast but not very useful since it gets every entry including duplicates

        Returns:
            int: row count
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            x = con.execute(self.sql_file_count).fetchone()[0]
        return x

    def hash_count(self) -> int:
        """number of unique entries in the FILE table.
           very slow but no duplicates.

        Returns:
            int: row count
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            x = con.execute(self.sql_hash_count).fetchone()[0]
        return x
    
    def custom_columns(self, columns: Iterable[str] = None) -> set[str]:
        """test provided columns against available.

        Args:
            columns (Iterable[str], optional): If None use all available.
            If no matches return all available columns.
            
            Defaults to None.

        Returns:
            set[str]: usable columns for generating queries
        """
        if columns is not None:
            clmns = set(columns).intersection(self._custom_columns)
            if len(clmns) > 0:
                return clmns
        return self.available_columns()
    
    @classmethod
    def available_columns(cls) -> set[str]:
        """usable column names

        Returns:
            set[str]: valid columns that can be used in queries
        """
        return set(cls._custom_columns)
    
    def sql_select_column_filter(self, columns: Iterable[str] = None, distinct: bool = False) -> str:
        """Generate a sql statement with optional columns and distinct

        Args:
            columns (Iterable[str], optional): which columns to select. 
                Defaults to None which will get all columns.
            distinct (bool, optional): only get unique/distinct items. Defaults to False.

        Returns:
            str: sql select statement
        """
        clmns = self.custom_columns(columns)
        selects = ','.join(clmns)
        if distinct:
            sql = f"SELECT {selects} FROM FILE WHERE file_size >= 0 GROUP BY {selects};"
        else:
            sql = f"SELECT {selects} FROM FILE;"
        return sql
    
    def enum_dicts(self, query: str) -> Iterator[dict]:
        """enumerates items in database using dictionary factory

        Args:
            query (str): sql statement for RDS database

        Yields:
            Iterator[dict]: all rows returned by query
        """
        file_uri = f"{self.path.as_uri()}?mode=ro"
        with sqlite3.connect(file_uri, uri=True) as con:
            con.row_factory = RDSReader.dict_factory
            for row in con.execute(query):
                yield row

    def enum_by_columns(self, columns: Iterable[str] = None, distinct: bool = False) -> Iterator[dict]:
        """get items from RDS database returning only specific column data

        Args:
            distinct (bool, optional): only get unique/distinct items. Defaults to False.
            columns (Iterable[str], optional): which columns to select. 
                Defaults to None which will get all columns.

        Yields:
            Iterator[dict]: all rows in dictionary form
        """
        sql = self.sql_select_column_filter(distinct=distinct, columns=columns)
        for itm in self.enum_dicts(sql):
            yield itm
    
    def enum_all(self, distinct: bool = False) -> Iterator[dict]:
        """get all items with default columns from RDS database

        Args:
            distinct (bool, optional): only get unique/distinct items. Defaults to False.

        Yields:
            Iterator[dict]: all rows in dictionary form
        """
        sql = self.sql_select_column_filter(distinct=distinct)
        for itm in self.enum_dicts(sql):
            yield itm

if __name__ == "__main__":
    pass