# Database intergration by s-raza (@pyrod)
from db.Models import *
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
#import sublert.config as cfg

class SLDB():
    
    def __init__(self, *args, **kwargs):
        
        self.conn_str = kwargs['conn_string'] if (kwargs.get('conn_string') is not None) else "sqlite:///sublert.db"
        self.engine = create_engine(self.conn_str)
        self.base = Base
        self.base.metadata.create_all(self.engine)
        self.session = scoped_session( sessionmaker(bind=self.engine) )
        self.domain = kwargs['domain'] if (kwargs.get('domain') is not None) else None
        
    def __get_domain_inst(self, domain_name):
        '''Get the instance of a domain from the database.'''
        return self.session.query(Domain).filter_by(name=domain_name).first()

    def __get_or_create_domain_inst(self, domain_name):
        '''Get the instance of a domain from the database, create it if it does not exist by name.'''
        domain_inst = self.session.query(Domain).filter_by(name=domain_name).first()
        
        if domain_inst is None:
            new_domain = self.add_domain(domain_name=domain_name)
            return new_domain
        else:
            return domain_inst       
        
    def add_domain(self, domain_name):
        '''Insert a new domain in the database'''
        
        inst = Domain(name=domain_name)
        self.session.add(inst)
        self.session.commit()

        return inst
        
    def domain_exists(self, domain_name):
        '''Check if a domain already exists in the database'''
        domain_inst = self.session.query(Domain).filter_by(name=domain_name).first()

        return False if domain_inst is None else True

    def subdomain_exists(self, subdomain_name):
        '''Check if a subdomain already exists in the database'''
        subdomain_inst = self.session.query(SubDomain).filter_by(name=subdomain_name).first()
        return False if subdomain_inst is None else True        
        
    def get_all_subdomains(self, domain):
        '''Return a list of all the subdomains for a given domain.'''
        domain_inst =  self.__get_domain_inst(domain)

        return [s.name for s in domain_inst.subdomains]
        
    def get_all_domains(self):
        '''Return a list of all the domains.'''
        
        return [s.name for s in self.session.query(Domain).all()]
        
    def insert_subdomains(self, domain_name, subdomains):
        '''Insert a list of subdomains or a single subdomain into the database for a given domain'''
        
        domain_inst = self.__get_domain_inst(domain_name)
        domain_inst.date_updated = func.now()
        
        if type(subdomains) == type([]):
            for sub in subdomains:
                domain_inst.subdomains.append(SubDomain(name=sub, date_added=func.now()))
        else:
            domain_inst.subdomains.append(SubDomain(name=subdomains, date_added=func.now()))
        
        self.session.commit()
        return domain_inst

    def delete_domain(self, domain):
        '''Delete a domain'''

        domain_inst = self.__get_domain_inst(domain)
        self.session.delete(domain_inst)
        self.session.commit()

    def delete_all_domains(self):
        '''Delete all domains'''
        
        domain_inst = self.session.query(Domain).all()
        
        for domain in domain_inst:
            self.session.delete(domain)
        
        self.session.commit()
        
    def delete_all_subdomains(self, domain):
        '''Delete all subdomains for a given domain'''
        
        domain_inst = self.__get_domain_inst(domain)
        
        for subdomain in domain_inst.subdomains:
            self.session.delete(subdomain)
        
        self.session.commit()         
        
        
        