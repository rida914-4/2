#!/usr/bin/env python

import os
import re
import sys
import stat
import errno
import plyvel
import shutil
import argparse
from fuse import FUSE, FuseOSError, Operations
from Passthrough import Passthrough


class FuseCustom(Passthrough):

	def __init__(self, root, lvldb):

		self.root = root
		self.lvldb = lvldb
		self.INODE_SIZE = 40 
		self.BLOCK_SIZE = 1024 
		self.INODE_PER_BLOCK = 25
		self.BLOCK_WRITEABLE = 41
		self.BLOCKS_PER_INODE = 8
		self.PER_FOURBYTE = 4
	        self.db_dict = self.create_inode_from_leveldb()
	
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
	
		dirents.extend(map(str, self.get_total_db_files()))
	
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

		
		block_id, inode_position, offset = self.process_file_path(path)
		
		inode_index, file_list = self.get_inode_file_list(block_id, inode_position, offset)
		
		index = 0
		for data_content in buf:
			# split into 1k chunk and save in the files
			put_key_value_into_level_db(file_list[index], data_content)
			
			# Donot add into the files 
			#except 8KB limit
			if index >=8:
				continue
		
		return buf
   
	def process_file_path(self, path):
		''' Generic function to process the path and get blocks 
		and data from the leveldb persistent storage '''
		
		number = re.findall('\d+',path)[0]
		print("PROCESS - Number : {}".format(number))
		
		# out of 41 blocks lets get the block id by dividing 
		# the file name by 25 -total number of inodes
		block_id = int(number)/25
		inode_position = int(number) % 25
		
		inode_size = inode_position * self.INODE_SIZE
		
		print("PROCESS - Block ID = {}".format(block_id))
		print("PROCESS - Inode position in the block = {}".format(inode_position))
		print("PROCESS - Inode size in the block = {}".format(inode_size))
		
		offset = int(inode_position) * self.INODE_SIZE
		print("PROCESS - Offset = Number {} x INODE SIZE {} =  : {}".format(inode_position, self.INODE_SIZE, offset))
		
		return block_id, inode_position, offset
	
	def read(self, path, length, offset, fh):
		''' Read the files '''
		
		print "read",path,offset,fh, length
		block_id, inode_position, offset = self.process_file_path(path)
		inode_number, content = self.get_block_data(block_id, inode_position, offset)

#		no_of_blocks = getblocks(self.filename, offset, self.BLOCKS_PER_INODE* 4 , 4 )
		
		
#		block_index = 0
		#content = ""
#		print "No of blocks", no_of_blocks
#		while no_of_blocks > 0:
#			block_id = getblocks(self.filename, lfs_offset, block_index* 4 , 4 )
#			print "block_id", block_id
#			content += read_at(self.filename,block_id, self.BLOCK_SIZE)
#			no_of_blocks = no_of_blocks - 1
		return content

	
    	def release(self, path, fh):
		return os.close(fh)	
		
	def get_total_db_files(self):
	
		''' We go throught the first 41 blocks and parse each inode byte to 
		verify that we have indeed 1024 files in the inode '''
		file_list = list()
	
		for block_id, inode_block in self.db_dict.iteritems():

			if int(block_id) <= self.BLOCK_WRITEABLE:
			
				inode_array = bytearray(inode_block)
			
				for offset in range(0, self.INODE_SIZE * self.INODE_PER_BLOCK, self.INODE_SIZE):
				
					#print("Block ID : {}, index : {} ".format(block_id, offset))
					file_number_bin = (inode_array[offset:offset+self.PER_FOURBYTE], 0)
				
					if file_number_bin != (b'', 0):
						file_number = int(bytes(file_number_bin[0]).encode('hex'), 16)
						#print("Block ID : {}, index : {}, file number : {}, ".format(block_id, offset, file_number))
						file_list.append(file_number)
					else:
						print 'Empty byte {}'.format(file_number_bin)
			
			
						
		return list(set(file_list))
		
		
	def get_inode_file_list(self, block_id, inode_position, offset):
	
		files = list()
		print '>>>>>>', block_id, inode_position, offset
		raw_block = self.db_dict['{}'.format(block_id)]


		for index, a in enumerate(range(offset-40, offset, 4)):

			if index == 0:
				inode_number = int(bytes(((raw_block, 0)[0][a:a+4], 0)).encode('hex'), 16)
		
			if index in range(1, 9):
				raw_content = ((raw_block, 0)[0][a:a+4], 0)
				
				file_number = int(bytes(raw_content[0]).encode('hex'), 16)
				
				# Test : Check if the file numbers and the offsets are correct
				#print 'File number {}, {}, {}, {}'.format(file_number, a, a+4, raw_content)
				files.append(file_number)
		return 	inode_number, files
		
	
	def get_block_data(self, block_id, inode_position, offset):
		''' Pull the data from the db return dictionary '''

		files = list()
		print '>>>>>>', block_id, inode_position, offset
		raw_block = self.db_dict['{}'.format(block_id)]


		for index, a in enumerate(range(offset-40, offset, 4)):

			if index == 0:
				inode_number = int(bytes(((raw_block, 0)[0][a:a+4], 0)).encode('hex'), 16)
		
			if index in range(1, 9):
				raw_content = ((raw_block, 0)[0][a:a+4], 0)
				
				file_number = int(bytes(raw_content[0]).encode('hex'), 16)
				
				# Test : Check if the file numbers and the offsets are correct
				#print 'File number {}, {}, {}, {}'.format(file_number, a, a+4, raw_content)
				files.append(file_number)
		
		# Draw content out of the files
		file_data = ""
		for file_name in files:
			print file_name
			file_data += self.db_dict['{}'.format(file_name)]
			
		return inode_number, file_data	
		
	# ------------------------- DB functions ----------------------------------- #
	
	def hex_to_int(self, data):
		return int(data.encode('hex'), 16)	
	

	def get_key_values_from_leveldb(self):
		""" Fetch the values from the levelDB """
	
		temp = dict()
		db = plyvel.DB(self.lvldb, create_if_missing=True)
	
		# Create 30 files for show
		for file_id in range(0, 30):
			db.put(b'{}'.format(file_id), b'{}'.format("Get some 1kb data"))
		

		for key, value in db:
			temp[key] = value

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




	def create_inode_from_leveldb(self):
		temp = dict()
		if os.path.exists(self.lvldb):
			shutil.rmtree(self.lvldb)
		db = plyvel.DB(self.lvldb, create_if_missing=True)
	
		# Create the inode and block strucutre
		#0 : | 0 | 1 | 2 | ... | 25 |                  |                   |
		#<----------inodes---------> <---- block -----> <-- empty bytes ---> 
	
		empty_bytes = bytes(4)
		byte_length = 4
		counter = self.BLOCK_WRITEABLE
		old_file_no = int(1)
	
		files_created = list()
		# Create 41 (0 - 40) blocks as keys

		for block_id in range(1, self.BLOCK_WRITEABLE + 1):

			full_block = bytearray(b'')

			# Keep track of older blocks
		
			# Create 25 inode each of 40 bytes

			""" Create full 25 x 40B = 1000B block to save in the database """
			for inode_no in range(old_file_no, old_file_no + self.INODE_PER_BLOCK):
			
				#if int(old_file_no) >= int(INODE_PER_BLOCK * BLOCK_WRITEABLE):
				#	print "ending"
				#	continue
			
				files_created.append(inode_no)			
				#print INODE_PER_BLOCK * BLOCK_WRITEABLE, old_file_no, old_file_no + INODE_PER_BLOCK
				# Start with an empty inode
				inode = bytearray(b'')
			
				# Put inode number here 
				inode_bytes =  ('%%0%dx' % (byte_length << 1) % inode_no).decode('hex')[-byte_length:]
				inode += inode_bytes
				#print("Inode = {}".format(len(inode_bytes)))
	#			print("Putting {} as inode no. {}".format((inode_bytes, 0), self.hex_to_int(inode_bytes)))			
			
				# Put 8 x 4B data here
				indirect_data_bound = counter + self.BLOCKS_PER_INODE
			
				indirect_data = bytearray(b'')
				counter_old = counter
			
			
				#print("Counter {}, last bound {}".format(counter, indirect_data_bound))
			
				for data_block in range(counter, indirect_data_bound):
					indirect_bytes =  ('%%0%dx' % (byte_length << 1) % data_block).decode('hex')[-byte_length:]
	#				print("Putting 8x 4B data ({}) {} as  {}".format(data_block, (indirect_bytes, 0), self.hex_to_int(indirect_bytes)))	
		
					indirect_data += indirect_bytes
				
				counter += 8
			
				#print(len(indirect_data))			
				# !Test : Check if right number of inodes and data blocks are created : PASSED
				#print "Block : {}, Inode : {}, Data block starts from {} and ends at {} , Bytes: \n".format(block_id, inode_no, counter_old, counter)
				inode += indirect_data
				#print("Inode = {}".format(len(inode)))
			
				# Put extra 4 bytes here
				for a in range(0, 4):
					inode += empty_bytes
				print("Put empty bytes {} as {}".format((empty_bytes, 0), self.hex_to_int(empty_bytes)))

				# Inode complete. Concatenate it with the other 25 inodes in a block
				#print("Inode = {}".format(len(inode)))
				full_block += inode
			
				# Test : Final block correct  : PASSED
			
				#print "Final Block ID({}) single inode : ({})".format(block_id, len(bytes(full_block)))
				#print "Final Block ({}) : {} , {}:".format(len(bytes(full_block)), (full_block, 0), self.hex_to_int(bytes(full_block)))
			
				old_file_no = inode_no + 1
			
			#print "Final Block ID({}) all inode : ({}), last seen inode {} ".format(block_id, len(bytes(full_block)), inode_no)
			#print '----------------------'
		
			db.put(b'{}'.format(block_id), b'{}'.format(full_block))

			# Test : Convert the byte back to integer to check if the computation is correct : PASSED
			#inode_int = int(inode_bytes.encode('hex'), 16)
		
		# After the first 41 blocks , rest of the key value pair 
		# corresponds to the data blocks of each inode.
		# 25 inode in each block x 8 data blocks x 41 blocks
	
		total_blocks = self.INODE_PER_BLOCK * self.BLOCK_WRITEABLE * self.BLOCKS_PER_INODE
		#print("CREATING DATABASE - Total blocks = {}".format(total_blocks))
	
		for indirect_pointers in range(self.BLOCK_WRITEABLE + 1, total_blocks):
			db.put(b'{}'.format(indirect_pointers), b'{}'.format("GET 1kb data"))
	
		for key, value in db:
			temp[key] = b'{}'.format(value)
	
		db.close()
		#print 'Files created : {}'.format(files_created)
	
		return temp

	
            
            
def main(mountpoint, root, single, lvldb):

	if not single:
		single = True
		
	FUSE(FuseCustom(root, lvldb), mountpoint, nothreads=single,
         foreground=True, **{'allow_other': True})


if __name__ == '__main__':

    	# levelfs2.py -s -d <levelfs_mount_dir> <leveldb_path>
    
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
    
    
    
    
    
