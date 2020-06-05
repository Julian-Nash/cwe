from cwe import Database


def main():
    """ Loads the cve database """

    db = Database()
    db._build_database()


if __name__ == "__main__":
    main()
