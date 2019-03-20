# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/iso_checksums.py
# Compiled at: 2019-02-15 12:42:10
import json, os, threading, warnings, folder_central, foundation_tools
checksums = {}
updating_lock = threading.Lock()
checksums_lock = threading.Lock()

def clear_checksums():
    """
    Empty the in-memory and file representations of the cache.
    
    Returns:
      None
    """
    global checksums
    with checksums_lock:
        with open(folder_central.get_iso_checksums(), 'w+') as (fp):
            checksums['iso_checksums'] = {}
            json.dump(checksums, fp, indent=2)


def load_checksums():
    """
    Load the in-memory cache from the persistence file; create blank JSON
    template in file if non-existent.
    
    Returns:
      None
    """
    global checksums
    with checksums_lock:
        with open(folder_central.get_iso_checksums(), 'w+') as (fp):
            try:
                checksums = json.load(fp)
            except ValueError:
                checksums['iso_checksums'] = {}
                json.dump(checksums, fp, indent=2)


def add_checksum(filepath, md5):
    """
    Add an entry to the cache and update the persistence file.
    
    Arguments:
      filepath - string containing full path to file to be added to cache
      md5 - string containing md5 checksum of the file at 'filepath'
    Returns:
      None
    """
    if md5 is None:
        warnings.warn('cowardly refusing to add md5(None) for file %s' % filepath, stacklevel=2)
        return
    filepath = os.path.realpath(filepath)
    with checksums_lock:
        checksums['iso_checksums'][filepath] = {'md5': md5, 'mtime': os.path.getmtime(filepath)}
        with open(folder_central.get_iso_checksums(), 'w') as (fp):
            json.dump(checksums, fp, indent=2)
    return


def get_checksum(filepath, blocking=False):
    """
    Get the cache entry for the file at full path 'filepath'.
    
    If non-blocking, on cache miss start a background thread to update the whole
    cache based on contents of the ISO directories and return None.
    
    If blocking, on cache miss compute missing checksum, add to cache, and
    return it. Guaranteed to return a checksum.
    
    Returns:
      None - if non-blocking and cache miss
      an md5 checksum - if (non-blocking and cache hit) or (blocking)
    """
    filepath = os.path.realpath(filepath)
    with checksums_lock:
        retrieved = checksums['iso_checksums'].get(filepath)
        if retrieved:
            if retrieved.get('mtime') == os.path.getmtime(filepath):
                return retrieved.get('md5')
    if blocking:
        updated_checksum = foundation_tools.get_md5sum(filepath)
        add_checksum(filepath, updated_checksum)
        return updated_checksum
    update_checksums()
    return


def update_checksums(blocking=False):
    """
    Logic on whether or not to start requested update thread based on current
    state. If blocking, gets lock using blocking acquire(). If non-blocking,
    try to get lock using non-blocking acquire(False) and only start new thread
    if not one currently running.
    
    Returns:
      None - if no new thread was started
      a thread reference - if started, reference to new update thread
    """
    if blocking:
        updating_lock.acquire()
        return start_update_thread()
    if updating_lock.acquire(False):
        return start_update_thread()
    return


def start_update_thread():
    """
    Starts background update thread.
    
    Prerequisite:
      need to acquire updating_lock before calling this function!
    Returns:
      reference to update thread
    """
    checksum_thread = threading.Thread(target=update_checksums_worker)
    checksum_thread.daemon = True
    checksum_thread.start()
    return checksum_thread


def update_checksums_worker():
    """
    Loops over all files in ISO folders and updates checksum cache entry
    if calling get_checksum() on it results in cache miss. Update is done
    using foundation_tools.get_md5sum() on said file. Releases updating_lock
    upon completion.
    
    Returns:
      None
    """
    kvm_folder = folder_central.get_kvm_isos_folder()
    esx_folder = folder_central.get_esx_isos_folder()
    hyperv_folder = folder_central.get_hyperv_isos_folder()
    xen_folder = folder_central.get_xen_isos_folder()
    folders = [
     kvm_folder, esx_folder, hyperv_folder, xen_folder]
    for folder in folders:
        for filename in os.listdir(folder):
            if filename.startswith('.'):
                continue
            filepath = os.path.join(folder, filename)
            if not os.path.exists(filepath):
                try:
                    os.unlink(filepath)
                except Exception:
                    pass

                continue
            if get_checksum(filepath) is None:
                updated_checksum = foundation_tools.get_md5sum(filepath)
                add_checksum(filepath, updated_checksum)

    updating_lock.release()
    return


load_checksums()