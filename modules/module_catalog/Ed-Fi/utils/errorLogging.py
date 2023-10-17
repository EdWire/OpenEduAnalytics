import uuid

class ErrorLogging:
    def __init__(self, spark, oea, logger):
        self.spark = spark
        self.oea = oea
        self.logger = logger
        self.pipeline_id = None
        self.spark_session_id = spark.sparkContext.applicationId
        self.test_mode = True
        self.entity_logs = list()
        self.stage_logs = list()
        self.pipeline_logs = list()

    # Helper function to generate a random alphanumeric string of specified length
    def generate_random_alphanumeric(self, length):
        return uuid.uuid4().hex[:length]
    
    def create_log_dict(self, **kwargs):
        return kwargs

    def consolidate_logs(self, log_data, log_type):
        if log_type == 'entity':
            log_data['log_type'] = 'entity'
            self.entity_logs.append(log_data)
        elif log_type == 'stage':
            log_data['log_type'] = 'stage'
            self.stage_logs.append(log_data)
        elif log_type == 'pipeline':
            log_data['log_type'] = 'pipeline'
            self.pipeline_logs.append(log_data)
        else:
            raise ValueError('Invalid Log Type')
    def create_spark_df(self, log_type):
        if log_type == 'entity':
            df = self.spark.createDataFrame(self.entity_logs) 
        elif log_type == 'stage':
            df = self.spark.createDataFrame(self.stage_logs) 
        elif log_type == 'pipeline':
            df = self.spark.createDataFrame(self.pipeline_logs)
        else:
            raise ValueError('Invalid Log Type')
        
        return df
    
    def write_logs_to_delta_lake(self, df, log_type,destination_url):
        #TODO: Pending Edits
        self.logger.info('Dynamically over-write the partition')
        self.spark.conf.set("spark.sql.sources.partitionOverwriteMode", "dynamic")
        
        if log_type == 'entity':
            df.write.format('delta').mode('overwrite').partitionBy('etlType','entityType','entityName', 'pipelineExecutionId').save(destination_url)
        if log_type == 'pipeline':
            df.write.format('delta').mode('overwrite').partitionBy('pipelineExecutionId').save(destination_url)
        if log_type == 'stage':
            df.write.format('delta').mode('overwrite').partitionBy('stageName','pipelineExecutionId').save(destination_url)