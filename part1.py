#!/usr/bin/env python

import os
import re
import sys
import stat
import errno
import plyvel
import argparse
from fuse import FUSE, FuseOSError, Operations
from Passthrough import Passthrough

INODE_SIZE = 40 
BLOCK_SIZE = 1024 
BLOCK_WRITEABLE = 40


class FuseCustom(Passthrough):

	def __init__(self, root, lvldb):

		self.root = root
		self.lvldb = lvldb
	        self.db_dict = self.get_key_values_from_leveldb()
	
        # Helpers
	# =======
	def _full_path(self, partial, useFallBack=False):
	        if partial.startswith("/"):
	            partial = partial[1:]
            
	        # Find out the real path. 
	        path = primaryPath = os.path.join(self.fallbackPath if useFallBack else self.root, partial)
	        primaryDir = os.path.dirname(primaryPath)
	       
	        return path
      
	def getattr(self, path, fh=None):
		""" Mandatory function to get the attributes of the file system  """
	
		print("FUSE - Get the attributes of the file system.\n")
       		full_path = self._full_path(path)
        	#print("THIS IS THE PATH {}".format(full_path))
        
        	st = os.lstat(full_path)
        
        	attr_dict = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                                                        'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid', 'st_blocks')) 
        
        	#print('The attribute dictionary is as follows.\n{}'.format(attr_dict))
	        #attr_dict['st_mode'] = stat.S_IFDIR | 0444
        	return attr_dict

    	def readdir(self, path, fh):
    		""" This mandatory function is required to read the fuse 
    		mounted directory
    		 """
	    	print("FUSE - Reading the mounted directory.\n")
        	dirents = ['.', '..']
        
        
        	# This is the regular files that need to be mounted
        	full_path = self._full_path(path)

		for k, v in self.db_dict.iteritems():
			dirents.extend(["{}".format(k)])

		#print("Final directory entries: {}".format(dirents))
        	for r in list(set(dirents)):
        	    yield r

    	def open(self, path, flags):
        	print("FUSE - open the directory.\n")
        	full_path = self._full_path(path)
        	return os.open(full_path, flags)

    	def create(self, path, mode, fi=None):
        	print("FUSE - Create the mounted directory.\n")
        	full_path = self._full_path(path)
        	return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)
        
	def write(self, path, buf, offset, fh):
		print("Write operation called.pth:{} buf:{} offset:{} fh:{}\n".format(path, buf, offset, fh))
		#put_key_value_into_level_db(path.split('/')[-1], buf)
        	return os.write(fh, buf)
   
    	def read(self, path, length, offset, fh):
    
        	print("FUSE - Read operation is called for file {} .".format(path))
        	try:
        		file_contents = str(self.db_dict[path])
        	
        		print("File contents : {}\n".format(file_contents))
        	except Exception as e:
        		print(e)
        		file_contents = "error"

        	return file_contents

    	def release(self, path, fh):
		return os.close(fh)
		
	# ------------------------- DB functions ----------------------------------- #
		
	def hex_to_int(self, data):
		return int(data.encode('hex'), 16)	
	

	def get_key_values_from_leveldb(self):
		""" Fetch the values from the levelDB """
	
		temp = dict()
		db = plyvel.DB(self.lvldb, create_if_missing=True)

		data_bytes = ''
		byte_length = 1
		
		# Here we place the empty bytes each of 1024 size
		for byte_no in range(0, BLOCK_SIZE):
			data_bytes += ('%%0%dx' % (byte_length << 1) % 0).decode('hex')[-byte_length:]

		# Test : Right amount of bytes are saved in the persistent storage			
		print len(data_bytes), data_bytes

		# Create 30 files for show
		for file_id in range(0, 30):
			db.put(b'{}'.format(file_id), b'{}'.format("{}".format(data_bytes)))
		
		# Save it in the dictionary
		for key, value in db:
			temp[key] = value
		print temp
		db.close()
		return temp
	

	def put_key_value_into_level_db(self, key, value):
		""" Fetch the values from the levelDB """
	
		temp = dict()
		db = plyvel.DB(self.lvldb, create_if_missing=True)
	
		# add in the database
		db.put(b'{}'.format(key), b'{}'.format(value))	

		db.close()

		return 0
			
            
def main(mountpoint, root, single, lvldb):

	if not single:
		single = True
		
	FUSE(FuseCustom(root, lvldb), mountpoint, nothreads=single,
         foreground=True, **{'allow_other': True})


if __name__ == '__main__':

    	# levelfs1.py -s -d <levelfs_mount_dir> <leveldb_path>
    
    	parser = argparse.ArgumentParser()
	parser.add_argument('-s', "--single", help='Single Thread')
	parser.add_argument('-d', "--dir", help='Directory to be mounted', required=True)
	parser.add_argument('-m', "--mountpt", help='Mount point', required=True)
	parser.add_argument('-l', "--level", help='level DB', required=True)

	args = parser.parse_args()
	
	# Parse the arguments
	mountpoint = args.mountpt
	root = args.dir
	single = args.single
	lvldb = args.level
	
	main(mountpoint, root, single, lvldb)
    
    
    
    
    
    
