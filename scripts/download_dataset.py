import os
import gzip
import tarfile
import zipfile

from tqdm.auto import tqdm


DEFAULT_DATASET_DIR = ".datasets"
URLS = {
    "blogs": "http://moreno.ss.uci.edu/blogs.dat",
    "ego-facebook": "http://konect.uni-koblenz.de/downloads/tsv/ego-facebook.tar.bz2",
    "arenas-email": "http://konect.uni-koblenz.de/downloads/tsv/arenas-email.tar.bz2",
    "friendship": "http://konect.uni-koblenz.de/downloads/tsv/petster-friendships-hamster.tar.bz2"
}

class TqdmUpTo(tqdm): 
    last_block = 0
    def update_to(self, block_num=1, block_size=1, total_size=None):
        if total_size is not None:
            self.total = total_size
        self.update((block_num - self.last_block) * block_size)
        self.last_block = block_num

def prepare_dir(root, fold):
    path = os.path.join(root, fold)
    if not os.path.exists(path):
        os.makedirs(path)
    return path

def download_url(url, fold, filename=None):
    import urllib
    if filename is None:
        filename = os.path.basename(url)
    
    fpath = os.path.join(fold, filename)

    if os.path.exists(fpath):
        print("File has been downloaded")
        return fpath

    try:
        with TqdmUpTo(unit='B', unit_scale=True, unit_divisor=1024, miniters=1, desc=filename) as t:
            urllib.request.urlretrieve(
                url, fpath,
                reporthook=t.update_to
            )
    except (urllib.error.URLError, IOError) as e:
        if url[:5] == 'https':
                url = url.replace('https:', 'http:')
                print('Failed download. Trying https -> http instead.'
                      ' Downloading ' + url + ' to ' + fpath)
                with TqdmUpTo(unit='B', unit_scale=True, unit_divisor=1024, miniters=1, desc=filename) as t:
                    urllib.request.urlretrieve(
                        url, fpath,
                        reporthook=t.update_to
                    )
        else:
            raise e
    
    print(f"File is downloaded to {fpath}")
    return fpath

def _is_tarbz2(filename):
    return filename.endswith(".tar.bz2")

def _is_tarxz(filename):
    return filename.endswith(".tar.xz")

def _is_tar(filename):
    return filename.endswith(".tar")

def _is_targz(filename):
    return filename.endswith(".tar.gz")

def _is_tgz(filename):
    return filename.endswith(".tgz")

def _is_gzip(filename):
    return filename.endswith(".gz") and not filename.endswith(".tar.gz")

def _is_zip(filename):
    return filename.endswith(".zip")

def extract_archive(from_path, to_path=None, remove_finished=False):
    if to_path is None:
        to_path = os.path.dirname(from_path)

    if _is_tar(from_path):
        with tarfile.open(from_path, 'r') as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tar, path=to_path)
    elif _is_targz(from_path) or _is_tgz(from_path):
        with tarfile.open(from_path, 'r:gz') as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tar, path=to_path)
    elif _is_tarxz(from_path):
        with tarfile.open(from_path, 'r:xz') as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tar, path=to_path)
    elif _is_tarbz2(from_path):
        with tarfile.open(from_path, 'r:bz2') as tar:
            def is_within_directory(directory, target):
                
                abs_directory = os.path.abspath(directory)
                abs_target = os.path.abspath(target)
            
                prefix = os.path.commonprefix([abs_directory, abs_target])
                
                return prefix == abs_directory
            
            def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
            
                for member in tar.getmembers():
                    member_path = os.path.join(path, member.name)
                    if not is_within_directory(path, member_path):
                        raise Exception("Attempted Path Traversal in Tar File")
            
                tar.extractall(path, members, numeric_owner=numeric_owner) 
                
            
            safe_extract(tar, path=to_path)
    elif _is_gzip(from_path):
        to_path = os.path.join(to_path, os.path.splitext(os.path.basename(from_path))[0])
        with open(to_path, "wb") as out_f, gzip.GzipFile(from_path) as zip_f:
            out_f.write(zip_f.read())
    elif _is_zip(from_path):
        with zipfile.ZipFile(from_path, 'r') as z:
            z.extractall(to_path)
    else:
        raise ValueError("Extraction of {} not supported".format(from_path))

    if remove_finished:
        os.remove(from_path)


def prepare_blogs(fold=DEFAULT_DATASET_DIR):
    filename = "blogs.dat"
    target_fold = prepare_dir(fold, "blogs")
    
    download_url(URLS["blogs"], target_fold, filename)
    with open(os.path.join(target_fold, filename), "r") as f:
        lines = f.readlines()

    result = []
    lines = lines[1490 + 1490 + 2 + 4:]
    for line in lines:
        items = line.strip().split(" ")
        result.append(f"{items[0]} {items[1]} 1\n")

    with open(os.path.join(target_fold, "graph.txt"), "w+") as f:
        f.writelines(result)

def prepare_ego_facebook(fold=DEFAULT_DATASET_DIR):
    filename = "out.ego-facebook"
    target_fold = prepare_dir(fold, "ego_facebook")

    fpath = download_url(URLS["ego-facebook"], target_fold)
    extract_archive(fpath, target_fold)
    with open(os.path.join(target_fold, "ego-facebook", filename), "r") as f:
        lines = f.readlines()
    
    result = []
    lines = lines[2:]
    for line in lines:
        items = line.strip().split(" ")
        result.append(f"{items[0]} {items[1]} 1\n")

    with open(os.path.join(target_fold, "graph.txt"), "w+") as f:
        f.writelines(result)

def prepare_arenas_email(fold=DEFAULT_DATASET_DIR):
    filename = "out.arenas-email"
    target_fold = prepare_dir(fold, "arenas_email")
    fpath = download_url(URLS["arenas-email"], target_fold)
    extract_archive(fpath, target_fold)
    with open(os.path.join(target_fold, "arenas-email", filename), "r") as f:
        lines = f.readlines()
    
    result = []
    lines = lines[1:]
    for line in lines:
        items = line.strip().split(" ")
        result.append(f"{items[0]} {items[1]} 1\n")

    with open(os.path.join(target_fold, "graph.txt"), "w+") as f:
        f.writelines(result)

def prepare_friendship(fold=DEFAULT_DATASET_DIR):
    filename = "out.petster-friendships-hamster-uniq"
    target_fold = prepare_dir(fold, "friendship")
    fpath = download_url(URLS["friendship"], target_fold)
    extract_archive(fpath, target_fold)
    with open(os.path.join(target_fold, "petster-friendships-hamster", filename), "r") as f:
        lines = f.readlines()
    
    result = []
    lines = lines[1:]
    
    vid = 1
    id_vertex = {}

    for line in lines:
        [src, dist] = line.strip().split(" ")
        if id_vertex.get(src) == None:
            id_vertex[src] = vid
            vid += 1
        if id_vertex.get(dist) == None:
            id_vertex[dist] = vid
            vid += 1
            
        result.append(f"{id_vertex[src]} {id_vertex[dist]} 1\n")

    with open(os.path.join(target_fold, "graph.txt"), "w+") as f:
        f.writelines(result)


def main(args):
    if args.dataset == "blogs":
        prepare_blogs(fold=args.root)
    elif args.dataset == "ego-facebook":
        prepare_ego_facebook(fold=args.root)
    elif args.dataset == "arenas-email":
        prepare_arenas_email(fold=args.root)
    elif args.dataset == "friendship":
        prepare_friendship(fold=args.root)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser("Download datasets")
    parser.add_argument("-d", "--dataset", default="", type=str)
    parser.add_argument("-r", "--root", default=DEFAULT_DATASET_DIR, type=str)

    args = parser.parse_args()

    if args.dataset not in URLS.keys():
        print("Supporting datasets: ")
        for k in URLS.keys():
            print("-", k)
        exit(0)

    main(args)