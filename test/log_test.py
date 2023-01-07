import logging


def log_init():
    logging.basicConfig(format='%(levelname)s - %(message)s', level=logging.INFO, filename='../logs/Detection_log.log', filemode='w')
    # logging.info("this is an info,555")

def operate():
    logging.info('zihanshu')

if __name__ == '__main__':
    log_init()
    operate()

