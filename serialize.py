from avro.datafile import DataFileReader
from avro.io import DatumReader

if __name__ == "__main__":
    # Десериализация файла
    # Из-за того, что данные о схеме содержатся в самом файле, вам не требуется явно ссылаться на схему
    reader = DataFileReader(open("users.avro", "rb"), DatumReader())

    for user in reader:
        print(user)

    reader.close()
